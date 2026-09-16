rule TTP_XOR_QUAD_CurrentVersionRun_929b {
  strings:
    $key_929b = { c1 f4 [2] e5 fa [2] ce d6 [2] e0 f4 [2] f4 ef [2] fb f5 [2] e5 e8 [2] e7 e9 [2] fc ef [2] e0 e8 [2] fc c7 }

  condition:
    any of them
}