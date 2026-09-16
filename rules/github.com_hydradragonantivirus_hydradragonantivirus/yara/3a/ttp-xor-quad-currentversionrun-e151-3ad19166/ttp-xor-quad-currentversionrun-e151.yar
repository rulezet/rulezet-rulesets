rule TTP_XOR_QUAD_CurrentVersionRun_e151 {
  strings:
    $key_e151 = { b2 3e [2] 96 30 [2] bd 1c [2] 93 3e [2] 87 25 [2] 88 3f [2] 96 22 [2] 94 23 [2] 8f 25 [2] 93 22 [2] 8f 0d }

  condition:
    any of them
}