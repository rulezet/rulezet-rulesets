rule TTP_XOR_QUAD_CurrentVersionRun_4ee8 {
  strings:
    $key_4ee8 = { 1d 87 [2] 39 89 [2] 12 a5 [2] 3c 87 [2] 28 9c [2] 27 86 [2] 39 9b [2] 3b 9a [2] 20 9c [2] 3c 9b [2] 20 b4 }

  condition:
    any of them
}