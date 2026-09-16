rule TTP_XOR_QUAD_CurrentVersionRun_4b54 {
  strings:
    $key_4b54 = { 18 3b [2] 3c 35 [2] 17 19 [2] 39 3b [2] 2d 20 [2] 22 3a [2] 3c 27 [2] 3e 26 [2] 25 20 [2] 39 27 [2] 25 08 }

  condition:
    any of them
}