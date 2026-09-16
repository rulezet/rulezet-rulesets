rule TTP_XOR_QUAD_CurrentVersionRun_ee53 {
  strings:
    $key_ee53 = { bd 3c [2] 99 32 [2] b2 1e [2] 9c 3c [2] 88 27 [2] 87 3d [2] 99 20 [2] 9b 21 [2] 80 27 [2] 9c 20 [2] 80 0f }

  condition:
    any of them
}