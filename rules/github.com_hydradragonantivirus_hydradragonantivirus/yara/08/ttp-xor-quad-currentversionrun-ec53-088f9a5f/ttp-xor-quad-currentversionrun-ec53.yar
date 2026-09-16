rule TTP_XOR_QUAD_CurrentVersionRun_ec53 {
  strings:
    $key_ec53 = { bf 3c [2] 9b 32 [2] b0 1e [2] 9e 3c [2] 8a 27 [2] 85 3d [2] 9b 20 [2] 99 21 [2] 82 27 [2] 9e 20 [2] 82 0f }

  condition:
    any of them
}