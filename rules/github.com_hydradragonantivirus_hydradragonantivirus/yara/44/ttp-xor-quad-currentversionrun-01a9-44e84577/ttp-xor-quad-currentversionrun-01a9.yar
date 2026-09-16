rule TTP_XOR_QUAD_CurrentVersionRun_01a9 {
  strings:
    $key_01a9 = { 52 c6 [2] 76 c8 [2] 5d e4 [2] 73 c6 [2] 67 dd [2] 68 c7 [2] 76 da [2] 74 db [2] 6f dd [2] 73 da [2] 6f f5 }

  condition:
    any of them
}