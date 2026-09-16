rule TTP_XOR_QUAD_CurrentVersionRun_dd37 {
  strings:
    $key_dd37 = { 8e 58 [2] aa 56 [2] 81 7a [2] af 58 [2] bb 43 [2] b4 59 [2] aa 44 [2] a8 45 [2] b3 43 [2] af 44 [2] b3 6b }

  condition:
    any of them
}