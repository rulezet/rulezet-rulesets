rule TTP_XOR_QUAD_CurrentVersionRun_c300 {
  strings:
    $key_c300 = { 90 6f [2] b4 61 [2] 9f 4d [2] b1 6f [2] a5 74 [2] aa 6e [2] b4 73 [2] b6 72 [2] ad 74 [2] b1 73 [2] ad 5c }

  condition:
    any of them
}