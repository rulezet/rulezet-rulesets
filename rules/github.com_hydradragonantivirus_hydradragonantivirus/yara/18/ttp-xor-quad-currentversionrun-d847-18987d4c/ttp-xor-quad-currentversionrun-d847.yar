rule TTP_XOR_QUAD_CurrentVersionRun_d847 {
  strings:
    $key_d847 = { 8b 28 [2] af 26 [2] 84 0a [2] aa 28 [2] be 33 [2] b1 29 [2] af 34 [2] ad 35 [2] b6 33 [2] aa 34 [2] b6 1b }

  condition:
    any of them
}