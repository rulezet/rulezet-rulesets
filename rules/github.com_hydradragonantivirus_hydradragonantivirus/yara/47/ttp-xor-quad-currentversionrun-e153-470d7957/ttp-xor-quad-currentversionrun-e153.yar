rule TTP_XOR_QUAD_CurrentVersionRun_e153 {
  strings:
    $key_e153 = { b2 3c [2] 96 32 [2] bd 1e [2] 93 3c [2] 87 27 [2] 88 3d [2] 96 20 [2] 94 21 [2] 8f 27 [2] 93 20 [2] 8f 0f }

  condition:
    any of them
}