rule apt32_macos_dropper {
  meta:
    author = "Amnesty Tech"

  strings:
    $s1  = "setStartup" ascii
    $s2  = "getSizeDataLoader" ascii
    $s3  = "GET_LAUNCHNAME" ascii
    $s4  = "GET_PROCESSNAME" ascii
    $s5  = "getProcessnameRoot" ascii
    $s6  = "getProcessnameUser" ascii
    $s7  = "getProcessPathRoot" ascii
    $s8  = "getLabelnameRoot" ascii
    $s9  = "getLabelnameUser" ascii
    $s10 = "stringFromHex" ascii
    $s11 = "_b64_decode_ex" ascii

  condition:
    (uint16(0) == 0xfacf or uint16(0) == 0xface) and 9 of them
}