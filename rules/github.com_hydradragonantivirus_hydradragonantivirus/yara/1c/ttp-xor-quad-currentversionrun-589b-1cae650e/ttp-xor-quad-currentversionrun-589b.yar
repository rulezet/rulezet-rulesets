rule TTP_XOR_QUAD_CurrentVersionRun_589b {
  strings:
    $key_589b = { 0b f4 [2] 2f fa [2] 04 d6 [2] 2a f4 [2] 3e ef [2] 31 f5 [2] 2f e8 [2] 2d e9 [2] 36 ef [2] 2a e8 [2] 36 c7 }

  condition:
    any of them
}