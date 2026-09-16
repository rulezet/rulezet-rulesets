rule TTP_XOR_QUAD_CurrentVersionRun_ede9 {
  strings:
    $key_ede9 = { be 86 [2] 9a 88 [2] b1 a4 [2] 9f 86 [2] 8b 9d [2] 84 87 [2] 9a 9a [2] 98 9b [2] 83 9d [2] 9f 9a [2] 83 b5 }

  condition:
    any of them
}