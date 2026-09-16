rule TTP_XOR_QUAD_CurrentVersionRun_59f4 {
  strings:
    $key_59f4 = { 0a 9b [2] 2e 95 [2] 05 b9 [2] 2b 9b [2] 3f 80 [2] 30 9a [2] 2e 87 [2] 2c 86 [2] 37 80 [2] 2b 87 [2] 37 a8 }

  condition:
    any of them
}