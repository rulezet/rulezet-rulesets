rule TTP_XOR_QUAD_CurrentVersionRun_d036 {
  strings:
    $key_d036 = { 83 59 [2] a7 57 [2] 8c 7b [2] a2 59 [2] b6 42 [2] b9 58 [2] a7 45 [2] a5 44 [2] be 42 [2] a2 45 [2] be 6a }

  condition:
    any of them
}