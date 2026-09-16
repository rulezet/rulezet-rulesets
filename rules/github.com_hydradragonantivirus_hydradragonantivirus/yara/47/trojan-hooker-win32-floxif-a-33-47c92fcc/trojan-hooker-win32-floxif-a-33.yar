rule Trojan_Hooker_Win32_Floxif_A_33 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9f8a5ce1e9a023e1d5df034981fd7f77298046e754aaacd8863cc3f909b3a79"

  strings:
    $x1  = "### ERROR CreateProcess [%d] CmdLine=%s" fullword wide
    $x2  = "### ERROR CompareProductInfoDB() ExecuteReader. [%s]" fullword wide
    $s3  = "ERROR CompareProductInfoDB() ExecuteReader. [%s]" fullword wide
    $s4  = "### InTouchService: ERROR CreateProcessAsUser() [%d]" fullword wide
    $s5  = "### ERROR IsConnectReadyNetwork: ImpersonateLoggedOnUser() [%d]" fullword wide
    $s6  = "### ERROR CreateAndWriteFile() GetTempFile() [%d]" fullword wide
    $s7  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s8  = "### ERROR UpdateAdviveMessage() ExecuteNonQuery %s" fullword wide
    $s9  = "### CreateProcess Error [%d]" fullword wide
    $s10 = "InTouchService: ERROR CreateProcessAsUser() [%d]" fullword wide
    $s11 = "### WinHttpQueryHeaders CONTENT_LENGTH Error [%d]" fullword wide
    $s12 = " ERROR IsConnectReadyNetwork: ImpersonateLoggedOnUser() [%d]" fullword wide
    $s13 = "ERROR CreateAndWriteFile() GetTempFile() [%d]" fullword wide
    $s14 = "### ERROR EPAUDFOpenKeyEx() [%d](%s)" fullword wide
    $s15 = "### ---> GetDeviceID_32() Start" fullword wide
    $s16 = "### ---> GetSerialUSBID_32() Start" fullword wide
    $s17 = "ERROR UpdateAdviveMessage() ExecuteNonQuery %s" fullword wide
    $s18 = "### ERROR ModuleMoveFile: DeleteFile() TempFile=%s [%d]" fullword wide
    $s19 = "### ERROR IsConnectReadyNetwork: GetProcAddress() [%d]" fullword wide
    $s20 = "### ---> EbapiSection Lock IN thread[0x%x] CExtEscape::GetSerialUSBID()" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}