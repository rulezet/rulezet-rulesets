rule TTP_XOR_QUAD_CurrentVersionRun_d855 {
  strings:
    $key_d855 = { 8b 3a [2] af 34 [2] 84 18 [2] aa 3a [2] be 21 [2] b1 3b [2] af 26 [2] ad 27 [2] b6 21 [2] aa 26 [2] b6 09 }

  condition:
    any of them
}