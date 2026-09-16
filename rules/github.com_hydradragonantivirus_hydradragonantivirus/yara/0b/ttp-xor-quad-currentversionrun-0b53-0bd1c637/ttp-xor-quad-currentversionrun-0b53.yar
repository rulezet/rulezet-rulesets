rule TTP_XOR_QUAD_CurrentVersionRun_0b53 {
  strings:
    $key_0b53 = { 58 3c [2] 7c 32 [2] 57 1e [2] 79 3c [2] 6d 27 [2] 62 3d [2] 7c 20 [2] 7e 21 [2] 65 27 [2] 79 20 [2] 65 0f }

  condition:
    any of them
}