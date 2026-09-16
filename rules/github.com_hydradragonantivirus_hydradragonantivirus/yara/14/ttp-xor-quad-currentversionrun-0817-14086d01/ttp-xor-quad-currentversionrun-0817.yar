rule TTP_XOR_QUAD_CurrentVersionRun_0817 {
  strings:
    $key_0817 = { 5b 78 [2] 7f 76 [2] 54 5a [2] 7a 78 [2] 6e 63 [2] 61 79 [2] 7f 64 [2] 7d 65 [2] 66 63 [2] 7a 64 [2] 66 4b }

  condition:
    any of them
}