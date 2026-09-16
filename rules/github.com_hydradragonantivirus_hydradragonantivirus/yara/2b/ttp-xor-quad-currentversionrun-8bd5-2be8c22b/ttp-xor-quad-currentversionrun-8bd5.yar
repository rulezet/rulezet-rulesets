rule TTP_XOR_QUAD_CurrentVersionRun_8bd5 {
  strings:
    $key_8bd5 = { d8 ba [2] fc b4 [2] d7 98 [2] f9 ba [2] ed a1 [2] e2 bb [2] fc a6 [2] fe a7 [2] e5 a1 [2] f9 a6 [2] e5 89 }

  condition:
    any of them
}