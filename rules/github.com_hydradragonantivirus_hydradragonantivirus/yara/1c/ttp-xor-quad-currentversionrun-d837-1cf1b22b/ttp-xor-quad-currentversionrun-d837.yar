rule TTP_XOR_QUAD_CurrentVersionRun_d837 {
  strings:
    $key_d837 = { 8b 58 [2] af 56 [2] 84 7a [2] aa 58 [2] be 43 [2] b1 59 [2] af 44 [2] ad 45 [2] b6 43 [2] aa 44 [2] b6 6b }

  condition:
    any of them
}