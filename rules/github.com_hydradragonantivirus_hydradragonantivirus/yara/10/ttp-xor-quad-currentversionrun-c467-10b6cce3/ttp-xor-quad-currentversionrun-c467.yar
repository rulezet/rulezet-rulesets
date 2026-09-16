rule TTP_XOR_QUAD_CurrentVersionRun_c467 {
  strings:
    $key_c467 = { 97 08 [2] b3 06 [2] 98 2a [2] b6 08 [2] a2 13 [2] ad 09 [2] b3 14 [2] b1 15 [2] aa 13 [2] b6 14 [2] aa 3b }

  condition:
    any of them
}