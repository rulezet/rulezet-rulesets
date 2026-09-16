rule TTP_XOR_QUAD_CurrentVersionRun_2c15 {
  strings:
    $key_2c15 = { 7f 7a [2] 5b 74 [2] 70 58 [2] 5e 7a [2] 4a 61 [2] 45 7b [2] 5b 66 [2] 59 67 [2] 42 61 [2] 5e 66 [2] 42 49 }

  condition:
    any of them
}