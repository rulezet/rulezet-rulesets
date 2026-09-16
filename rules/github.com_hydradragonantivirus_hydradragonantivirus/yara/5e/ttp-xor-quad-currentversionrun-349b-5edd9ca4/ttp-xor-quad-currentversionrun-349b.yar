rule TTP_XOR_QUAD_CurrentVersionRun_349b {
  strings:
    $key_349b = { 67 f4 [2] 43 fa [2] 68 d6 [2] 46 f4 [2] 52 ef [2] 5d f5 [2] 43 e8 [2] 41 e9 [2] 5a ef [2] 46 e8 [2] 5a c7 }

  condition:
    any of them
}