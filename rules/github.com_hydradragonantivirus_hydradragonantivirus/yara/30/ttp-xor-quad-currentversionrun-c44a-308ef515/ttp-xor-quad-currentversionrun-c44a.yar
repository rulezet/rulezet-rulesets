rule TTP_XOR_QUAD_CurrentVersionRun_c44a {
  strings:
    $key_c44a = { 97 25 [2] b3 2b [2] 98 07 [2] b6 25 [2] a2 3e [2] ad 24 [2] b3 39 [2] b1 38 [2] aa 3e [2] b6 39 [2] aa 16 }

  condition:
    any of them
}