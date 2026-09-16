rule TTP_XOR_QUAD_CurrentVersionRun_e14e {
  strings:
    $key_e14e = { b2 21 [2] 96 2f [2] bd 03 [2] 93 21 [2] 87 3a [2] 88 20 [2] 96 3d [2] 94 3c [2] 8f 3a [2] 93 3d [2] 8f 12 }

  condition:
    any of them
}