rule TTP_XOR_QUAD_CurrentVersionRun_8edb {
  strings:
    $key_8edb = { dd b4 [2] f9 ba [2] d2 96 [2] fc b4 [2] e8 af [2] e7 b5 [2] f9 a8 [2] fb a9 [2] e0 af [2] fc a8 [2] e0 87 }

  condition:
    any of them
}