rule TTP_XOR_QUAD_CurrentVersionRun_5cae {
  strings:
    $key_5cae = { 0f c1 [2] 2b cf [2] 00 e3 [2] 2e c1 [2] 3a da [2] 35 c0 [2] 2b dd [2] 29 dc [2] 32 da [2] 2e dd [2] 32 f2 }

  condition:
    any of them
}