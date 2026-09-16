rule TTP_XOR_QUAD_CurrentVersionRun_e486 {
  strings:
    $key_e486 = { b7 e9 [2] 93 e7 [2] b8 cb [2] 96 e9 [2] 82 f2 [2] 8d e8 [2] 93 f5 [2] 91 f4 [2] 8a f2 [2] 96 f5 [2] 8a da }

  condition:
    any of them
}