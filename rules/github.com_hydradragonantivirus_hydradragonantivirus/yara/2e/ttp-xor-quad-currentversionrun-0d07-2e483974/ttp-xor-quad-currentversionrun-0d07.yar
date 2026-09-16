rule TTP_XOR_QUAD_CurrentVersionRun_0d07 {
  strings:
    $key_0d07 = { 5e 68 [2] 7a 66 [2] 51 4a [2] 7f 68 [2] 6b 73 [2] 64 69 [2] 7a 74 [2] 78 75 [2] 63 73 [2] 7f 74 [2] 63 5b }

  condition:
    any of them
}