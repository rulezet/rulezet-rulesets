rule TTP_XOR_QUAD_CurrentVersionRun_68ae {
  strings:
    $key_68ae = { 3b c1 [2] 1f cf [2] 34 e3 [2] 1a c1 [2] 0e da [2] 01 c0 [2] 1f dd [2] 1d dc [2] 06 da [2] 1a dd [2] 06 f2 }

  condition:
    any of them
}