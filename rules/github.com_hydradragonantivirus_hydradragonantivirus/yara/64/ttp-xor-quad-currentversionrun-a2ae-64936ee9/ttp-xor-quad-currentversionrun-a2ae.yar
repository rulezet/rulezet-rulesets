rule TTP_XOR_QUAD_CurrentVersionRun_a2ae {
  strings:
    $key_a2ae = { f1 c1 [2] d5 cf [2] fe e3 [2] d0 c1 [2] c4 da [2] cb c0 [2] d5 dd [2] d7 dc [2] cc da [2] d0 dd [2] cc f2 }

  condition:
    any of them
}