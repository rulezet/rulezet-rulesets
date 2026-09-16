rule TTP_XOR_QUAD_CurrentVersionRun_d033 {
  strings:
    $key_d033 = { 83 5c [2] a7 52 [2] 8c 7e [2] a2 5c [2] b6 47 [2] b9 5d [2] a7 40 [2] a5 41 [2] be 47 [2] a2 40 [2] be 6f }

  condition:
    any of them
}