rule TTP_XOR_QUAD_CurrentVersionRun_80cd {
  strings:
    $key_80cd = { d3 a2 [2] f7 ac [2] dc 80 [2] f2 a2 [2] e6 b9 [2] e9 a3 [2] f7 be [2] f5 bf [2] ee b9 [2] f2 be [2] ee 91 }

  condition:
    any of them
}