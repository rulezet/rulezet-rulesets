rule TTP_XOR_QUAD_CurrentVersionRun_8bd1 {
  strings:
    $key_8bd1 = { d8 be [2] fc b0 [2] d7 9c [2] f9 be [2] ed a5 [2] e2 bf [2] fc a2 [2] fe a3 [2] e5 a5 [2] f9 a2 [2] e5 8d }

  condition:
    any of them
}