rule TTP_XOR_QUAD_CurrentVersionRun_c44b {
  strings:
    $key_c44b = { 97 24 [2] b3 2a [2] 98 06 [2] b6 24 [2] a2 3f [2] ad 25 [2] b3 38 [2] b1 39 [2] aa 3f [2] b6 38 [2] aa 17 }

  condition:
    any of them
}