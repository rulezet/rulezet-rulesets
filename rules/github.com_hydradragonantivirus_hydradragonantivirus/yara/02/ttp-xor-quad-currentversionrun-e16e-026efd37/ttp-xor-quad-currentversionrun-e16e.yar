rule TTP_XOR_QUAD_CurrentVersionRun_e16e {
  strings:
    $key_e16e = { b2 01 [2] 96 0f [2] bd 23 [2] 93 01 [2] 87 1a [2] 88 00 [2] 96 1d [2] 94 1c [2] 8f 1a [2] 93 1d [2] 8f 32 }

  condition:
    any of them
}