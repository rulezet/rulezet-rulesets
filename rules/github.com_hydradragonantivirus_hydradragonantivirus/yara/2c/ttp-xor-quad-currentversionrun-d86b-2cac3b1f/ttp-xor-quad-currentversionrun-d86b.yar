rule TTP_XOR_QUAD_CurrentVersionRun_d86b {
  strings:
    $key_d86b = { 8b 04 [2] af 0a [2] 84 26 [2] aa 04 [2] be 1f [2] b1 05 [2] af 18 [2] ad 19 [2] b6 1f [2] aa 18 [2] b6 37 }

  condition:
    any of them
}