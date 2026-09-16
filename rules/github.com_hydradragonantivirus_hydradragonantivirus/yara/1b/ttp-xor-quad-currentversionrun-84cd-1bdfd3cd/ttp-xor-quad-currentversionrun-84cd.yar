rule TTP_XOR_QUAD_CurrentVersionRun_84cd {
  strings:
    $key_84cd = { d7 a2 [2] f3 ac [2] d8 80 [2] f6 a2 [2] e2 b9 [2] ed a3 [2] f3 be [2] f1 bf [2] ea b9 [2] f6 be [2] ea 91 }

  condition:
    any of them
}