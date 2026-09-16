rule TTP_XOR_QUAD_CurrentVersionRun_1cae {
  strings:
    $key_1cae = { 4f c1 [2] 6b cf [2] 40 e3 [2] 6e c1 [2] 7a da [2] 75 c0 [2] 6b dd [2] 69 dc [2] 72 da [2] 6e dd [2] 72 f2 }

  condition:
    any of them
}