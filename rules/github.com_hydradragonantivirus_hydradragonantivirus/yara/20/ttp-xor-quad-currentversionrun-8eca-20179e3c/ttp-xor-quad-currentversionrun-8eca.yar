rule TTP_XOR_QUAD_CurrentVersionRun_8eca {
  strings:
    $key_8eca = { dd a5 [2] f9 ab [2] d2 87 [2] fc a5 [2] e8 be [2] e7 a4 [2] f9 b9 [2] fb b8 [2] e0 be [2] fc b9 [2] e0 96 }

  condition:
    any of them
}