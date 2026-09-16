rule TTP_XOR_QUAD_CurrentVersionRun_c310 {
  strings:
    $key_c310 = { 90 7f [2] b4 71 [2] 9f 5d [2] b1 7f [2] a5 64 [2] aa 7e [2] b4 63 [2] b6 62 [2] ad 64 [2] b1 63 [2] ad 4c }

  condition:
    any of them
}