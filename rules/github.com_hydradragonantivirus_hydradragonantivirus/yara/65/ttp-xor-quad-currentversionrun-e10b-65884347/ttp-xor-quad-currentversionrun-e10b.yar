rule TTP_XOR_QUAD_CurrentVersionRun_e10b {
  strings:
    $key_e10b = { b2 64 [2] 96 6a [2] bd 46 [2] 93 64 [2] 87 7f [2] 88 65 [2] 96 78 [2] 94 79 [2] 8f 7f [2] 93 78 [2] 8f 57 }

  condition:
    any of them
}