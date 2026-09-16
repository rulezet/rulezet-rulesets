rule TTP_XOR_QUAD_CurrentVersionRun_c35a {
  strings:
    $key_c35a = { 90 35 [2] b4 3b [2] 9f 17 [2] b1 35 [2] a5 2e [2] aa 34 [2] b4 29 [2] b6 28 [2] ad 2e [2] b1 29 [2] ad 06 }

  condition:
    any of them
}