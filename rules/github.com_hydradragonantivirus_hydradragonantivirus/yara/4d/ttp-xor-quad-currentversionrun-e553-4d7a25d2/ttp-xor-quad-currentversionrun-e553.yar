rule TTP_XOR_QUAD_CurrentVersionRun_e553 {
  strings:
    $key_e553 = { b6 3c [2] 92 32 [2] b9 1e [2] 97 3c [2] 83 27 [2] 8c 3d [2] 92 20 [2] 90 21 [2] 8b 27 [2] 97 20 [2] 8b 0f }

  condition:
    any of them
}