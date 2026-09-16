rule TTP_XOR_QUAD_CurrentVersionRun_c37a {
  strings:
    $key_c37a = { 90 15 [2] b4 1b [2] 9f 37 [2] b1 15 [2] a5 0e [2] aa 14 [2] b4 09 [2] b6 08 [2] ad 0e [2] b1 09 [2] ad 26 }

  condition:
    any of them
}