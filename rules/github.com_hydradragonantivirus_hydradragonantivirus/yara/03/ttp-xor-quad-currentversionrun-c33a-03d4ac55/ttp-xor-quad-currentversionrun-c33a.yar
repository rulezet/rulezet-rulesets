rule TTP_XOR_QUAD_CurrentVersionRun_c33a {
  strings:
    $key_c33a = { 90 55 [2] b4 5b [2] 9f 77 [2] b1 55 [2] a5 4e [2] aa 54 [2] b4 49 [2] b6 48 [2] ad 4e [2] b1 49 [2] ad 66 }

  condition:
    any of them
}