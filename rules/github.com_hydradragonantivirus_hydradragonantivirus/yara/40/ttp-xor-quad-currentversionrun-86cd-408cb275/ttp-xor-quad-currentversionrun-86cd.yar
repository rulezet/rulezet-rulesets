rule TTP_XOR_QUAD_CurrentVersionRun_86cd {
  strings:
    $key_86cd = { d5 a2 [2] f1 ac [2] da 80 [2] f4 a2 [2] e0 b9 [2] ef a3 [2] f1 be [2] f3 bf [2] e8 b9 [2] f4 be [2] e8 91 }

  condition:
    any of them
}