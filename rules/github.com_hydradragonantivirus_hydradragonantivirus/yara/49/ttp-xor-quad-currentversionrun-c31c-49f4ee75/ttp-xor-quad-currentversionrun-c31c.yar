rule TTP_XOR_QUAD_CurrentVersionRun_c31c {
  strings:
    $key_c31c = { 90 73 [2] b4 7d [2] 9f 51 [2] b1 73 [2] a5 68 [2] aa 72 [2] b4 6f [2] b6 6e [2] ad 68 [2] b1 6f [2] ad 40 }

  condition:
    any of them
}