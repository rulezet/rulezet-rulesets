rule TTP_XOR_QUAD_CurrentVersionRun_dd58 {
  strings:
    $key_dd58 = { 8e 37 [2] aa 39 [2] 81 15 [2] af 37 [2] bb 2c [2] b4 36 [2] aa 2b [2] a8 2a [2] b3 2c [2] af 2b [2] b3 04 }

  condition:
    any of them
}