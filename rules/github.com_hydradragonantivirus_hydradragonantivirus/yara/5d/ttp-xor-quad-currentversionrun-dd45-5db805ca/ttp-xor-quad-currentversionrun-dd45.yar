rule TTP_XOR_QUAD_CurrentVersionRun_dd45 {
  strings:
    $key_dd45 = { 8e 2a [2] aa 24 [2] 81 08 [2] af 2a [2] bb 31 [2] b4 2b [2] aa 36 [2] a8 37 [2] b3 31 [2] af 36 [2] b3 19 }

  condition:
    any of them
}