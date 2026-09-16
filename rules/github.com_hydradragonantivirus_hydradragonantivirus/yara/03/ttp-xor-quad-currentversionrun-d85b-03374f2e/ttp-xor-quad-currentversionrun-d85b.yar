rule TTP_XOR_QUAD_CurrentVersionRun_d85b {
  strings:
    $key_d85b = { 8b 34 [2] af 3a [2] 84 16 [2] aa 34 [2] be 2f [2] b1 35 [2] af 28 [2] ad 29 [2] b6 2f [2] aa 28 [2] b6 07 }

  condition:
    any of them
}