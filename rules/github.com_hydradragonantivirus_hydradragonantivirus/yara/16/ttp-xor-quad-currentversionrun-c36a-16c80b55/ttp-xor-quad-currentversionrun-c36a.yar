rule TTP_XOR_QUAD_CurrentVersionRun_c36a {
  strings:
    $key_c36a = { 90 05 [2] b4 0b [2] 9f 27 [2] b1 05 [2] a5 1e [2] aa 04 [2] b4 19 [2] b6 18 [2] ad 1e [2] b1 19 [2] ad 36 }

  condition:
    any of them
}