rule TTP_XOR_QUAD_CurrentVersionRun_e17c {
  strings:
    $key_e17c = { b2 13 [2] 96 1d [2] bd 31 [2] 93 13 [2] 87 08 [2] 88 12 [2] 96 0f [2] 94 0e [2] 8f 08 [2] 93 0f [2] 8f 20 }

  condition:
    any of them
}