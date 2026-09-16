rule TTP_XOR_QUAD_CurrentVersionRun_e49b {
  strings:
    $key_e49b = { b7 f4 [2] 93 fa [2] b8 d6 [2] 96 f4 [2] 82 ef [2] 8d f5 [2] 93 e8 [2] 91 e9 [2] 8a ef [2] 96 e8 [2] 8a c7 }

  condition:
    any of them
}