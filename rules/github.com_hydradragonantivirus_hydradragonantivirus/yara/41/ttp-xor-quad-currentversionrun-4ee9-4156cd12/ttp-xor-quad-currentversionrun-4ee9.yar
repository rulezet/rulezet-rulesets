rule TTP_XOR_QUAD_CurrentVersionRun_4ee9 {
  strings:
    $key_4ee9 = { 1d 86 [2] 39 88 [2] 12 a4 [2] 3c 86 [2] 28 9d [2] 27 87 [2] 39 9a [2] 3b 9b [2] 20 9d [2] 3c 9a [2] 20 b5 }

  condition:
    any of them
}