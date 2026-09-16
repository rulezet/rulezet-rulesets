rule TTP_XOR_QUAD_CurrentVersionRun_e253 {
  strings:
    $key_e253 = { b1 3c [2] 95 32 [2] be 1e [2] 90 3c [2] 84 27 [2] 8b 3d [2] 95 20 [2] 97 21 [2] 8c 27 [2] 90 20 [2] 8c 0f }

  condition:
    any of them
}