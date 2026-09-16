rule TTP_XOR_QUAD_CurrentVersionRun_d023 {
  strings:
    $key_d023 = { 83 4c [2] a7 42 [2] 8c 6e [2] a2 4c [2] b6 57 [2] b9 4d [2] a7 50 [2] a5 51 [2] be 57 [2] a2 50 [2] be 7f }

  condition:
    any of them
}