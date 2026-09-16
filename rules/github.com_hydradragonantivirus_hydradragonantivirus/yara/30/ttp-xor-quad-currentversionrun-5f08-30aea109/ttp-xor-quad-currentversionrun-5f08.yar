rule TTP_XOR_QUAD_CurrentVersionRun_5f08 {
  strings:
    $key_5f08 = { 0c 67 [2] 28 69 [2] 03 45 [2] 2d 67 [2] 39 7c [2] 36 66 [2] 28 7b [2] 2a 7a [2] 31 7c [2] 2d 7b [2] 31 54 }

  condition:
    any of them
}