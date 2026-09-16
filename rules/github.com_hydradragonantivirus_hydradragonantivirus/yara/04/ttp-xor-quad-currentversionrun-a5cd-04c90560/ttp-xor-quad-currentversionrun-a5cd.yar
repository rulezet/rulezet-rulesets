rule TTP_XOR_QUAD_CurrentVersionRun_a5cd {
  strings:
    $key_a5cd = { f6 a2 [2] d2 ac [2] f9 80 [2] d7 a2 [2] c3 b9 [2] cc a3 [2] d2 be [2] d0 bf [2] cb b9 [2] d7 be [2] cb 91 }

  condition:
    any of them
}