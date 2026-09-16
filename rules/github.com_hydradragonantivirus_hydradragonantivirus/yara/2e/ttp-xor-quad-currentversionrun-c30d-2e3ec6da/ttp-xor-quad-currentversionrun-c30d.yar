rule TTP_XOR_QUAD_CurrentVersionRun_c30d {
  strings:
    $key_c30d = { 90 62 [2] b4 6c [2] 9f 40 [2] b1 62 [2] a5 79 [2] aa 63 [2] b4 7e [2] b6 7f [2] ad 79 [2] b1 7e [2] ad 51 }

  condition:
    any of them
}