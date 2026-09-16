rule dsng_installer_dll_stringset {
  meta:
    author = "Matt Brooks, @cmatthewbrooks"

  strings:
    $s1 = "KCOM Server Security Guard"
    $s2 = "LoadFlgDllFun"
    $s3 = "Installv" fullword
    $s4 = "Dll path %s"
    $s5 = "MainFunVvv"
    $s6 = "http://dsas.asdf.com/"

  condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
    2 of them
}