rule TTP_XOR_QUAD_CurrentVersionRun_d74c {
  strings:
    $key_d74c = { 84 23 [2] a0 2d [2] 8b 01 [2] a5 23 [2] b1 38 [2] be 22 [2] a0 3f [2] a2 3e [2] b9 38 [2] a5 3f [2] b9 10 }

  condition:
    any of them
}