rule TTP_XOR_QUAD_CurrentVersionRun_389b {
  strings:
    $key_389b = { 6b f4 [2] 4f fa [2] 64 d6 [2] 4a f4 [2] 5e ef [2] 51 f5 [2] 4f e8 [2] 4d e9 [2] 56 ef [2] 4a e8 [2] 56 c7 }

  condition:
    any of them
}