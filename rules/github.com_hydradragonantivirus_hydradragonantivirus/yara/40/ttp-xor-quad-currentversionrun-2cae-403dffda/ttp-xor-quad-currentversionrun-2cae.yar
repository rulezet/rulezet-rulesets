rule TTP_XOR_QUAD_CurrentVersionRun_2cae {
  strings:
    $key_2cae = { 7f c1 [2] 5b cf [2] 70 e3 [2] 5e c1 [2] 4a da [2] 45 c0 [2] 5b dd [2] 59 dc [2] 42 da [2] 5e dd [2] 42 f2 }

  condition:
    any of them
}