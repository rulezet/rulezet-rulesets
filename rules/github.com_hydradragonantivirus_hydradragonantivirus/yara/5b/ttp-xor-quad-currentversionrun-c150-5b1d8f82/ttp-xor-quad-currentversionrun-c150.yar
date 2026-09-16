rule TTP_XOR_QUAD_CurrentVersionRun_c150 {
  strings:
    $key_c150 = { 92 3f [2] b6 31 [2] 9d 1d [2] b3 3f [2] a7 24 [2] a8 3e [2] b6 23 [2] b4 22 [2] af 24 [2] b3 23 [2] af 0c }

  condition:
    any of them
}