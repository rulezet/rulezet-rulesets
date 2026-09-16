rule TTP_XOR_QUAD_CurrentVersionRun_c34c {
  strings:
    $key_c34c = { 90 23 [2] b4 2d [2] 9f 01 [2] b1 23 [2] a5 38 [2] aa 22 [2] b4 3f [2] b6 3e [2] ad 38 [2] b1 3f [2] ad 10 }

  condition:
    any of them
}