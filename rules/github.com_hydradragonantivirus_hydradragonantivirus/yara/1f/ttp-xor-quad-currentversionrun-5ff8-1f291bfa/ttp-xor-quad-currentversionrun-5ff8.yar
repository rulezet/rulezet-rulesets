rule TTP_XOR_QUAD_CurrentVersionRun_5ff8 {
  strings:
    $key_5ff8 = { 0c 97 [2] 28 99 [2] 03 b5 [2] 2d 97 [2] 39 8c [2] 36 96 [2] 28 8b [2] 2a 8a [2] 31 8c [2] 2d 8b [2] 31 a4 }

  condition:
    any of them
}