rule TTP_XOR_QUAD_CurrentVersionRun_a0ae {
  strings:
    $key_a0ae = { f3 c1 [2] d7 cf [2] fc e3 [2] d2 c1 [2] c6 da [2] c9 c0 [2] d7 dd [2] d5 dc [2] ce da [2] d2 dd [2] ce f2 }

  condition:
    any of them
}