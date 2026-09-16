rule TTP_XOR_QUAD_CurrentVersionRun_7a53 {
  strings:
    $key_7a53 = { 29 3c [2] 0d 32 [2] 26 1e [2] 08 3c [2] 1c 27 [2] 13 3d [2] 0d 20 [2] 0f 21 [2] 14 27 [2] 08 20 [2] 14 0f }

  condition:
    any of them
}