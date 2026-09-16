rule TTP_XOR_QUAD_CurrentVersionRun_92cd {
  strings:
    $key_92cd = { c1 a2 [2] e5 ac [2] ce 80 [2] e0 a2 [2] f4 b9 [2] fb a3 [2] e5 be [2] e7 bf [2] fc b9 [2] e0 be [2] fc 91 }

  condition:
    any of them
}