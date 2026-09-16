rule TTP_XOR_QUAD_CurrentVersionRun_4b78 {
  strings:
    $key_4b78 = { 18 17 [2] 3c 19 [2] 17 35 [2] 39 17 [2] 2d 0c [2] 22 16 [2] 3c 0b [2] 3e 0a [2] 25 0c [2] 39 0b [2] 25 24 }

  condition:
    any of them
}