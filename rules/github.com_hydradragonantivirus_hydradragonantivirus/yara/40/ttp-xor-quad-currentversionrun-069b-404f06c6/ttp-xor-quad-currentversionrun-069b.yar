rule TTP_XOR_QUAD_CurrentVersionRun_069b {
  strings:
    $key_069b = { 55 f4 [2] 71 fa [2] 5a d6 [2] 74 f4 [2] 60 ef [2] 6f f5 [2] 71 e8 [2] 73 e9 [2] 68 ef [2] 74 e8 [2] 68 c7 }

  condition:
    any of them
}