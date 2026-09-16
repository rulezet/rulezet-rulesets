rule TTP_XOR_QUAD_CurrentVersionRun_dd5b {
  strings:
    $key_dd5b = { 8e 34 [2] aa 3a [2] 81 16 [2] af 34 [2] bb 2f [2] b4 35 [2] aa 28 [2] a8 29 [2] b3 2f [2] af 28 [2] b3 07 }

  condition:
    any of them
}