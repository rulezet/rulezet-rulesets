rule TTP_XOR_QUAD_CurrentVersionRun_8bd2 {
  strings:
    $key_8bd2 = { d8 bd [2] fc b3 [2] d7 9f [2] f9 bd [2] ed a6 [2] e2 bc [2] fc a1 [2] fe a0 [2] e5 a6 [2] f9 a1 [2] e5 8e }

  condition:
    any of them
}