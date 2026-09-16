rule TTP_XOR_QUAD_CurrentVersionRun_21a9 {
  strings:
    $key_21a9 = { 72 c6 [2] 56 c8 [2] 7d e4 [2] 53 c6 [2] 47 dd [2] 48 c7 [2] 56 da [2] 54 db [2] 4f dd [2] 53 da [2] 4f f5 }

  condition:
    any of them
}