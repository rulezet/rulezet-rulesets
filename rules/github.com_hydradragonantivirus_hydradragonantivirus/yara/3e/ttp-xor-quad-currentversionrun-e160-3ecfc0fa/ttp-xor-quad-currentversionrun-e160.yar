rule TTP_XOR_QUAD_CurrentVersionRun_e160 {
  strings:
    $key_e160 = { b2 0f [2] 96 01 [2] bd 2d [2] 93 0f [2] 87 14 [2] 88 0e [2] 96 13 [2] 94 12 [2] 8f 14 [2] 93 13 [2] 8f 3c }

  condition:
    any of them
}