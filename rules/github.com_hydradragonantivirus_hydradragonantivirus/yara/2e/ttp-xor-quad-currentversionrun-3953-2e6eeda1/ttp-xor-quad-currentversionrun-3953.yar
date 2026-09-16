rule TTP_XOR_QUAD_CurrentVersionRun_3953 {
  strings:
    $key_3953 = { 6a 3c [2] 4e 32 [2] 65 1e [2] 4b 3c [2] 5f 27 [2] 50 3d [2] 4e 20 [2] 4c 21 [2] 57 27 [2] 4b 20 [2] 57 0f }

  condition:
    any of them
}