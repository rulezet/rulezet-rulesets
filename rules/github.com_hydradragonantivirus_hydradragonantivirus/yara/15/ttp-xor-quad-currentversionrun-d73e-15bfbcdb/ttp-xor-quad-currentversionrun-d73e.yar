rule TTP_XOR_QUAD_CurrentVersionRun_d73e {
  strings:
    $key_d73e = { 84 51 [2] a0 5f [2] 8b 73 [2] a5 51 [2] b1 4a [2] be 50 [2] a0 4d [2] a2 4c [2] b9 4a [2] a5 4d [2] b9 62 }

  condition:
    any of them
}