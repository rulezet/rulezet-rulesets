rule TTP_XOR_QUAD_CurrentVersionRun_4b48 {
  strings:
    $key_4b48 = { 18 27 [2] 3c 29 [2] 17 05 [2] 39 27 [2] 2d 3c [2] 22 26 [2] 3c 3b [2] 3e 3a [2] 25 3c [2] 39 3b [2] 25 14 }

  condition:
    any of them
}