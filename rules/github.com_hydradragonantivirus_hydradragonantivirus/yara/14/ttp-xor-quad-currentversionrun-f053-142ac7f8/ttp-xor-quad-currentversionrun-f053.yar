rule TTP_XOR_QUAD_CurrentVersionRun_f053 {
  strings:
    $key_f053 = { a3 3c [2] 87 32 [2] ac 1e [2] 82 3c [2] 96 27 [2] 99 3d [2] 87 20 [2] 85 21 [2] 9e 27 [2] 82 20 [2] 9e 0f }

  condition:
    any of them
}