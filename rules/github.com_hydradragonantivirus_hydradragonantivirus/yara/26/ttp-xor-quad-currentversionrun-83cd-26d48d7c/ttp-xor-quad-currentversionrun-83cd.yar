rule TTP_XOR_QUAD_CurrentVersionRun_83cd {
  strings:
    $key_83cd = { d0 a2 [2] f4 ac [2] df 80 [2] f1 a2 [2] e5 b9 [2] ea a3 [2] f4 be [2] f6 bf [2] ed b9 [2] f1 be [2] ed 91 }

  condition:
    any of them
}