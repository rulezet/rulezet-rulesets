rule TTP_XOR_QUAD_CurrentVersionRun_d051 {
  strings:
    $key_d051 = { 83 3e [2] a7 30 [2] 8c 1c [2] a2 3e [2] b6 25 [2] b9 3f [2] a7 22 [2] a5 23 [2] be 25 [2] a2 22 [2] be 0d }

  condition:
    any of them
}