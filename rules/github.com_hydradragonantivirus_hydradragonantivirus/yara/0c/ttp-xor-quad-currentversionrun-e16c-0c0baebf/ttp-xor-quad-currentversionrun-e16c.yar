rule TTP_XOR_QUAD_CurrentVersionRun_e16c {
  strings:
    $key_e16c = { b2 03 [2] 96 0d [2] bd 21 [2] 93 03 [2] 87 18 [2] 88 02 [2] 96 1f [2] 94 1e [2] 8f 18 [2] 93 1f [2] 8f 30 }

  condition:
    any of them
}