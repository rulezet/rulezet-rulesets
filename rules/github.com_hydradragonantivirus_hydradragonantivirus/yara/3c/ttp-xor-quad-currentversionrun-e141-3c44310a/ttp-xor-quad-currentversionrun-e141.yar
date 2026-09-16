rule TTP_XOR_QUAD_CurrentVersionRun_e141 {
  strings:
    $key_e141 = { b2 2e [2] 96 20 [2] bd 0c [2] 93 2e [2] 87 35 [2] 88 2f [2] 96 32 [2] 94 33 [2] 8f 35 [2] 93 32 [2] 8f 1d }

  condition:
    any of them
}