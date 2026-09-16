rule ARKBIRD_SOLG_CRIM_FIN7_PS_Cryptor_Jun_2021_1: FILE {
  meta:
    description = "Detect PS Cryptor used by FIN7 for Diceloader and Carbanak"
    author      = "Arkbird_SOLG"
    id          = "26361500-c33e-59c8-a53f-a881966c71a7"
    date        = "2021-06-07"
    modified    = "2021-06-07"
    reference   = "https://twitter.com/z0ul_/status/1401795117678219267"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-07/FIN7/CRIM_FIN7_PS_Cryptor_Jun_2021_1.yara#L1-L28"
    license_url = "N/A"
    logic_hash  = "d7eadaa6dec75ecfa2f03860f41b39dbe9e7ffc9e6ad743497586356301ef67c"
    score       = 75
    quality     = 55
    tags        = "FILE"
    hash1       = "944e47dc9da19b753beba173214cdebea2aa3651c402dfacae2dde82c4fdaa43"
    hash2       = "fada67a9f89429d6c191cd6fef5d75cd7b49eebaa2e40d1dd1f9884b3038a23b"
    hash3       = "0f083aac77fb734a8e81fb9dff218f0414ac6c4c9a23b2832837fbc2c7e2031d"
    hash4       = "dc9442838b464e96281a32705c9b5958e4f45dbefd1ef4a885fac9898af0a4b7"
    hash5       = "fad295cf65552061dc553c21d89d8bbd0b02783c01f5e696232df6a14381c206"
    tlp         = "White"
    adversary   = "FIN7"

  strings:
    $s1  = { 3d 4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 44 65 66 6c 61 74 65 53 74 72 65 61 6d 28 5b 49 4f 2e 4d 65 6d 6f 72 79 53 74 72 65 61 6d 5d 5b 42 79 74 65 5b 5d [6-12] 5b 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 5d 3a 3a 44 65 63 6f 6d 70 72 65 73 73 29 }
    $s2  = "@([IntPtr],[UInt32],[UInt32],[UInt32])([IntPtr])"
    $s3  = ", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null"
    $s4  = "[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer("
    $s5  = ", $null, [System.Reflection.CallingConventions]::Any, @([string]), $null)"
    $s6  = "[AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals(("
    $s7  = ", [System.Reflection.CallingConventions]::Standard,"
    $s8  = "[System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef($"
    $s9  = "=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($"
    $s10 = "[System.Runtime.InteropServices.Marshal]::Copy($"
    $s11 = "=[IntPtr]::Zero"

  condition:
    filesize > 40KB and 8 of ($s*)
}