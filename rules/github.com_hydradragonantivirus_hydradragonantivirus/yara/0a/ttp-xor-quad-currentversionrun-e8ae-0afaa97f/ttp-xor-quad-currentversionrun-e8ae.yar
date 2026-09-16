rule TTP_XOR_QUAD_CurrentVersionRun_e8ae {
  strings:
    $key_e8ae = { bb c1 [2] 9f cf [2] b4 e3 [2] 9a c1 [2] 8e da [2] 81 c0 [2] 9f dd [2] 9d dc [2] 86 da [2] 9a dd [2] 86 f2 }

  condition:
    any of them
}