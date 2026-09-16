rule TTP_XOR_QUAD_CurrentVersionRun_d864 {
  strings:
    $key_d864 = { 8b 0b [2] af 05 [2] 84 29 [2] aa 0b [2] be 10 [2] b1 0a [2] af 17 [2] ad 16 [2] b6 10 [2] aa 17 [2] b6 38 }

  condition:
    any of them
}