rule TTP_XOR_QUAD_CurrentVersionRun_d845 {
  strings:
    $key_d845 = { 8b 2a [2] af 24 [2] 84 08 [2] aa 2a [2] be 31 [2] b1 2b [2] af 36 [2] ad 37 [2] b6 31 [2] aa 36 [2] b6 19 }

  condition:
    any of them
}