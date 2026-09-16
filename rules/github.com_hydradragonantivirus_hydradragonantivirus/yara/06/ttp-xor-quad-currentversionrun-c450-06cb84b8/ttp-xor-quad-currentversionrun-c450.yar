rule TTP_XOR_QUAD_CurrentVersionRun_c450 {
  strings:
    $key_c450 = { 97 3f [2] b3 31 [2] 98 1d [2] b6 3f [2] a2 24 [2] ad 3e [2] b3 23 [2] b1 22 [2] aa 24 [2] b6 23 [2] aa 0c }

  condition:
    any of them
}