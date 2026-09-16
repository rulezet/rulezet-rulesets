rule dsng_installer_dll_characteristics {
  meta:
    author = "Matt Brooks, @cmatthewbrooks"

  strings:
    $s1 = "dsng.dll"
    $s2 = "InstallD" fullword
    $s3 = "InstallZ" fullword

  condition:
        uint16(0) == 0x5A4D and

        uint32(uint32(0x3C)) == 0x00004550 and

    all of them
}