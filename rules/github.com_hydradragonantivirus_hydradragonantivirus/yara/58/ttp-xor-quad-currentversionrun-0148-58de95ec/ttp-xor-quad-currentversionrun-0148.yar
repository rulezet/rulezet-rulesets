rule TTP_XOR_QUAD_CurrentVersionRun_0148 {
  strings:
    $key_0148 = { 52 27 [2] 76 29 [2] 5d 05 [2] 73 27 [2] 67 3c [2] 68 26 [2] 76 3b [2] 74 3a [2] 6f 3c [2] 73 3b [2] 6f 14 }

  condition:
    any of them
}