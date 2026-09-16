rule TTP_XOR_QUAD_CurrentVersionRun_3da9 {
  strings:
    $key_3da9 = { 6e c6 [2] 4a c8 [2] 61 e4 [2] 4f c6 [2] 5b dd [2] 54 c7 [2] 4a da [2] 48 db [2] 53 dd [2] 4f da [2] 53 f5 }

  condition:
    any of them
}