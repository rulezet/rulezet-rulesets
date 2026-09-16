rule TTP_XOR_QUAD_CurrentVersionRun_c45a {
  strings:
    $key_c45a = { 97 35 [2] b3 3b [2] 98 17 [2] b6 35 [2] a2 2e [2] ad 34 [2] b3 29 [2] b1 28 [2] aa 2e [2] b6 29 [2] aa 06 }

  condition:
    any of them
}