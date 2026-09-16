rule TTP_XOR_QUAD_CurrentVersionRun_e17f {
  strings:
    $key_e17f = { b2 10 [2] 96 1e [2] bd 32 [2] 93 10 [2] 87 0b [2] 88 11 [2] 96 0c [2] 94 0d [2] 8f 0b [2] 93 0c [2] 8f 23 }

  condition:
    any of them
}