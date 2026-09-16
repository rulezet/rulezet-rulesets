rule TTP_XOR_QUAD_CurrentVersionRun_919b {
  strings:
    $key_919b = { c2 f4 [2] e6 fa [2] cd d6 [2] e3 f4 [2] f7 ef [2] f8 f5 [2] e6 e8 [2] e4 e9 [2] ff ef [2] e3 e8 [2] ff c7 }

  condition:
    any of them
}