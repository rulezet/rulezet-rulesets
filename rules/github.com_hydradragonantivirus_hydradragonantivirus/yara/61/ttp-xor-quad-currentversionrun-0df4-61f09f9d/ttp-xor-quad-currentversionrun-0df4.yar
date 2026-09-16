rule TTP_XOR_QUAD_CurrentVersionRun_0df4 {
  strings:
    $key_0df4 = { 5e 9b [2] 7a 95 [2] 51 b9 [2] 7f 9b [2] 6b 80 [2] 64 9a [2] 7a 87 [2] 78 86 [2] 63 80 [2] 7f 87 [2] 63 a8 }

  condition:
    any of them
}