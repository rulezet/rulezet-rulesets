rule TTP_XOR_QUAD_CurrentVersionRun_d844 {
  strings:
    $key_d844 = { 8b 2b [2] af 25 [2] 84 09 [2] aa 2b [2] be 30 [2] b1 2a [2] af 37 [2] ad 36 [2] b6 30 [2] aa 37 [2] b6 18 }

  condition:
    any of them
}