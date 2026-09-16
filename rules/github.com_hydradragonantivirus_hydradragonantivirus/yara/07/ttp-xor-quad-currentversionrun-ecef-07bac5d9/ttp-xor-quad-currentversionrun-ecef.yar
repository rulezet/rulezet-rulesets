rule TTP_XOR_QUAD_CurrentVersionRun_ecef {
  strings:
    $key_ecef = { bf 80 [2] 9b 8e [2] b0 a2 [2] 9e 80 [2] 8a 9b [2] 85 81 [2] 9b 9c [2] 99 9d [2] 82 9b [2] 9e 9c [2] 82 b3 }

  condition:
    any of them
}