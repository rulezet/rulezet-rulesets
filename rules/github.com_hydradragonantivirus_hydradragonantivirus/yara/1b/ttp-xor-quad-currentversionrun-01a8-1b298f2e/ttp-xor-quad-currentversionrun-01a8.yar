rule TTP_XOR_QUAD_CurrentVersionRun_01a8 {
  strings:
    $key_01a8 = { 52 c7 [2] 76 c9 [2] 5d e5 [2] 73 c7 [2] 67 dc [2] 68 c6 [2] 76 db [2] 74 da [2] 6f dc [2] 73 db [2] 6f f4 }

  condition:
    any of them
}