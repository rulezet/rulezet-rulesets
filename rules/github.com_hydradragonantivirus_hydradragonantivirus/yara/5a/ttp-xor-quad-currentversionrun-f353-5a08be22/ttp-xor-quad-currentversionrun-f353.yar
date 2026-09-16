rule TTP_XOR_QUAD_CurrentVersionRun_f353 {
  strings:
    $key_f353 = { a0 3c [2] 84 32 [2] af 1e [2] 81 3c [2] 95 27 [2] 9a 3d [2] 84 20 [2] 86 21 [2] 9d 27 [2] 81 20 [2] 9d 0f }

  condition:
    any of them
}