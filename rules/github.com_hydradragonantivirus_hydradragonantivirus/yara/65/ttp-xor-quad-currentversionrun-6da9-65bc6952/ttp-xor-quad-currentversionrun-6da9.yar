rule TTP_XOR_QUAD_CurrentVersionRun_6da9 {
  strings:
    $key_6da9 = { 3e c6 [2] 1a c8 [2] 31 e4 [2] 1f c6 [2] 0b dd [2] 04 c7 [2] 1a da [2] 18 db [2] 03 dd [2] 1f da [2] 03 f5 }

  condition:
    any of them
}