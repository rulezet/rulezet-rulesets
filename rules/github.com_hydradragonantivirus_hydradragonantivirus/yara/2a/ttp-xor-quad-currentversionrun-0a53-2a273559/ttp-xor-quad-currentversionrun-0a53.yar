rule TTP_XOR_QUAD_CurrentVersionRun_0a53 {
  strings:
    $key_0a53 = { 59 3c [2] 7d 32 [2] 56 1e [2] 78 3c [2] 6c 27 [2] 63 3d [2] 7d 20 [2] 7f 21 [2] 64 27 [2] 78 20 [2] 64 0f }

  condition:
    any of them
}