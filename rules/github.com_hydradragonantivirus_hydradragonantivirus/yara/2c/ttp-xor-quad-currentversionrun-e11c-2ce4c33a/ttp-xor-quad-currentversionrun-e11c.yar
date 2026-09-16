rule TTP_XOR_QUAD_CurrentVersionRun_e11c {
  strings:
    $key_e11c = { b2 73 [2] 96 7d [2] bd 51 [2] 93 73 [2] 87 68 [2] 88 72 [2] 96 6f [2] 94 6e [2] 8f 68 [2] 93 6f [2] 8f 40 }

  condition:
    any of them
}