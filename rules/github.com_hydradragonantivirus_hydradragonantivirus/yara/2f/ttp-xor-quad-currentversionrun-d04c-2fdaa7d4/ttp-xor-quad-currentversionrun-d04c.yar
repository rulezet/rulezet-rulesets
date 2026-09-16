rule TTP_XOR_QUAD_CurrentVersionRun_d04c {
  strings:
    $key_d04c = { 83 23 [2] a7 2d [2] 8c 01 [2] a2 23 [2] b6 38 [2] b9 22 [2] a7 3f [2] a5 3e [2] be 38 [2] a2 3f [2] be 10 }

  condition:
    any of them
}