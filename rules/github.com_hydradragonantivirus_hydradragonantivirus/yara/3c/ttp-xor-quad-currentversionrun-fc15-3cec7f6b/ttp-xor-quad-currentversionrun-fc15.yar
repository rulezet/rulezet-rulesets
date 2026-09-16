rule TTP_XOR_QUAD_CurrentVersionRun_fc15 {
  strings:
    $key_fc15 = { af 7a [2] 8b 74 [2] a0 58 [2] 8e 7a [2] 9a 61 [2] 95 7b [2] 8b 66 [2] 89 67 [2] 92 61 [2] 8e 66 [2] 92 49 }

  condition:
    any of them
}