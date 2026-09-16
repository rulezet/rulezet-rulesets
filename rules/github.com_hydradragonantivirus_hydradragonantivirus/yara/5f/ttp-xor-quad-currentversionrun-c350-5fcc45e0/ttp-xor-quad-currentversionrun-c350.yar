rule TTP_XOR_QUAD_CurrentVersionRun_c350 {
  strings:
    $key_c350 = { 90 3f [2] b4 31 [2] 9f 1d [2] b1 3f [2] a5 24 [2] aa 3e [2] b4 23 [2] b6 22 [2] ad 24 [2] b1 23 [2] ad 0c }

  condition:
    any of them
}