rule TTP_XOR_QUAD_CurrentVersionRun_d8fb {
  strings:
    $key_d8fb = { 8b 94 [2] af 9a [2] 84 b6 [2] aa 94 [2] be 8f [2] b1 95 [2] af 88 [2] ad 89 [2] b6 8f [2] aa 88 [2] b6 a7 }

  condition:
    any of them
}