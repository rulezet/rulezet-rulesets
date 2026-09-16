rule TTP_XOR_QUAD_CurrentVersionRun_7623 {
  strings:
    $key_7623 = { 25 4c [2] 01 42 [2] 2a 6e [2] 04 4c [2] 10 57 [2] 1f 4d [2] 01 50 [2] 03 51 [2] 18 57 [2] 04 50 [2] 18 7f }

  condition:
    any of them
}