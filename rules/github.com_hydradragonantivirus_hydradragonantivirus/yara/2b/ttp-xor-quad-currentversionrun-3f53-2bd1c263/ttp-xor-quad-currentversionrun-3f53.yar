rule TTP_XOR_QUAD_CurrentVersionRun_3f53 {
  strings:
    $key_3f53 = { 6c 3c [2] 48 32 [2] 63 1e [2] 4d 3c [2] 59 27 [2] 56 3d [2] 48 20 [2] 4a 21 [2] 51 27 [2] 4d 20 [2] 51 0f }

  condition:
    any of them
}