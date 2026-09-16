rule TTP_XOR_QUAD_CurrentVersionRun_6319 {
  strings:
    $key_6319 = { 30 76 [2] 14 78 [2] 3f 54 [2] 11 76 [2] 05 6d [2] 0a 77 [2] 14 6a [2] 16 6b [2] 0d 6d [2] 11 6a [2] 0d 45 }

  condition:
    any of them
}