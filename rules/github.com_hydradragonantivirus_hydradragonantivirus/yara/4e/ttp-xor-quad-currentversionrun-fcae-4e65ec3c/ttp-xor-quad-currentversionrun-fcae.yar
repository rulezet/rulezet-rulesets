rule TTP_XOR_QUAD_CurrentVersionRun_fcae {
  strings:
    $key_fcae = { af c1 [2] 8b cf [2] a0 e3 [2] 8e c1 [2] 9a da [2] 95 c0 [2] 8b dd [2] 89 dc [2] 92 da [2] 8e dd [2] 92 f2 }

  condition:
    any of them
}