rule TTP_XOR_QUAD_CurrentVersionRun_28ae {
  strings:
    $key_28ae = { 7b c1 [2] 5f cf [2] 74 e3 [2] 5a c1 [2] 4e da [2] 41 c0 [2] 5f dd [2] 5d dc [2] 46 da [2] 5a dd [2] 46 f2 }

  condition:
    any of them
}