rule TTP_XOR_QUAD_CurrentVersionRun_7da9 {
  strings:
    $key_7da9 = { 2e c6 [2] 0a c8 [2] 21 e4 [2] 0f c6 [2] 1b dd [2] 14 c7 [2] 0a da [2] 08 db [2] 13 dd [2] 0f da [2] 13 f5 }

  condition:
    any of them
}