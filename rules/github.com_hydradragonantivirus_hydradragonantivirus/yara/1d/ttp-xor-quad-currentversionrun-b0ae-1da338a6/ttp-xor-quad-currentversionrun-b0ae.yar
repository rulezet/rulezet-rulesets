rule TTP_XOR_QUAD_CurrentVersionRun_b0ae {
  strings:
    $key_b0ae = { e3 c1 [2] c7 cf [2] ec e3 [2] c2 c1 [2] d6 da [2] d9 c0 [2] c7 dd [2] c5 dc [2] de da [2] c2 dd [2] de f2 }

  condition:
    any of them
}