rule TTP_XOR_QUAD_CurrentVersionRun_f953 {
  strings:
    $key_f953 = { aa 3c [2] 8e 32 [2] a5 1e [2] 8b 3c [2] 9f 27 [2] 90 3d [2] 8e 20 [2] 8c 21 [2] 97 27 [2] 8b 20 [2] 97 0f }

  condition:
    any of them
}