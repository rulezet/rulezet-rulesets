rule TTP_XOR_QUAD_CurrentVersionRun_3df4 {
  strings:
    $key_3df4 = { 6e 9b [2] 4a 95 [2] 61 b9 [2] 4f 9b [2] 5b 80 [2] 54 9a [2] 4a 87 [2] 48 86 [2] 53 80 [2] 4f 87 [2] 53 a8 }

  condition:
    any of them
}