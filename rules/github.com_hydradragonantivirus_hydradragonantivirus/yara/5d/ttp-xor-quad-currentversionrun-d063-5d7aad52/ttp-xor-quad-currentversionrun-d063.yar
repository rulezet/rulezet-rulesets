rule TTP_XOR_QUAD_CurrentVersionRun_d063 {
  strings:
    $key_d063 = { 83 0c [2] a7 02 [2] 8c 2e [2] a2 0c [2] b6 17 [2] b9 0d [2] a7 10 [2] a5 11 [2] be 17 [2] a2 10 [2] be 3f }

  condition:
    any of them
}