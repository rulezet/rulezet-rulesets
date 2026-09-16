rule TTP_XOR_QUAD_CurrentVersionRun_e15c {
  strings:
    $key_e15c = { b2 33 [2] 96 3d [2] bd 11 [2] 93 33 [2] 87 28 [2] 88 32 [2] 96 2f [2] 94 2e [2] 8f 28 [2] 93 2f [2] 8f 00 }

  condition:
    any of them
}