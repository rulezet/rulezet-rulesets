rule TTP_XOR_QUAD_CurrentVersionRun_0c15 {
  strings:
    $key_0c15 = { 5f 7a [2] 7b 74 [2] 50 58 [2] 7e 7a [2] 6a 61 [2] 65 7b [2] 7b 66 [2] 79 67 [2] 62 61 [2] 7e 66 [2] 62 49 }

  condition:
    any of them
}