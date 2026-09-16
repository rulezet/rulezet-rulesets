rule TTP_XOR_QUAD_CurrentVersionRun_dd57 {
  strings:
    $key_dd57 = { 8e 38 [2] aa 36 [2] 81 1a [2] af 38 [2] bb 23 [2] b4 39 [2] aa 24 [2] a8 25 [2] b3 23 [2] af 24 [2] b3 0b }

  condition:
    any of them
}