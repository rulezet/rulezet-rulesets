rule TTP_XOR_QUAD_CurrentVersionRun_dd79 {
  strings:
    $key_dd79 = { 8e 16 [2] aa 18 [2] 81 34 [2] af 16 [2] bb 0d [2] b4 17 [2] aa 0a [2] a8 0b [2] b3 0d [2] af 0a [2] b3 25 }

  condition:
    any of them
}