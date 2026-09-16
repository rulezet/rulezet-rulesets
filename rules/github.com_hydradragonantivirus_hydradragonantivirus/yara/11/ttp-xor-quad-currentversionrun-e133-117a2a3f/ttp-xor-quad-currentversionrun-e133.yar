rule TTP_XOR_QUAD_CurrentVersionRun_e133 {
  strings:
    $key_e133 = { b2 5c [2] 96 52 [2] bd 7e [2] 93 5c [2] 87 47 [2] 88 5d [2] 96 40 [2] 94 41 [2] 8f 47 [2] 93 40 [2] 8f 6f }

  condition:
    any of them
}