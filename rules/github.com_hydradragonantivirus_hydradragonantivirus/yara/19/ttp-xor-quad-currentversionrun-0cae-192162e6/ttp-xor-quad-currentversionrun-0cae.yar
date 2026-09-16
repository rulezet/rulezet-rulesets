rule TTP_XOR_QUAD_CurrentVersionRun_0cae {
  strings:
    $key_0cae = { 5f c1 [2] 7b cf [2] 50 e3 [2] 7e c1 [2] 6a da [2] 65 c0 [2] 7b dd [2] 79 dc [2] 62 da [2] 7e dd [2] 62 f2 }

  condition:
    any of them
}