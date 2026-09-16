rule TTP_XOR_QUAD_CurrentVersionRun_6a53 {
  strings:
    $key_6a53 = { 39 3c [2] 1d 32 [2] 36 1e [2] 18 3c [2] 0c 27 [2] 03 3d [2] 1d 20 [2] 1f 21 [2] 04 27 [2] 18 20 [2] 04 0f }

  condition:
    any of them
}