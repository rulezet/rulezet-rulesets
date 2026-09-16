rule TTP_XOR_QUAD_CurrentVersionRun_17b4 {
  strings:
    $key_17b4 = { 44 db [2] 60 d5 [2] 4b f9 [2] 65 db [2] 71 c0 [2] 7e da [2] 60 c7 [2] 62 c6 [2] 79 c0 [2] 65 c7 [2] 79 e8 }

  condition:
    any of them
}