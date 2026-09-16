rule TTP_XOR_QUAD_CurrentVersionRun_33a9 {
  strings:
    $key_33a9 = { 60 c6 [2] 44 c8 [2] 6f e4 [2] 41 c6 [2] 55 dd [2] 5a c7 [2] 44 da [2] 46 db [2] 5d dd [2] 41 da [2] 5d f5 }

  condition:
    any of them
}