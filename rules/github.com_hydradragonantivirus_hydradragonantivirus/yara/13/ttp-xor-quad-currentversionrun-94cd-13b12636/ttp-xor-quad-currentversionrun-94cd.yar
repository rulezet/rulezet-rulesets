rule TTP_XOR_QUAD_CurrentVersionRun_94cd {
  strings:
    $key_94cd = { c7 a2 [2] e3 ac [2] c8 80 [2] e6 a2 [2] f2 b9 [2] fd a3 [2] e3 be [2] e1 bf [2] fa b9 [2] e6 be [2] fa 91 }

  condition:
    any of them
}