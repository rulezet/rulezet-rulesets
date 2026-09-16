rule TTP_XOR_QUAD_CurrentVersionRun_e101 {
  strings:
    $key_e101 = { b2 6e [2] 96 60 [2] bd 4c [2] 93 6e [2] 87 75 [2] 88 6f [2] 96 72 [2] 94 73 [2] 8f 75 [2] 93 72 [2] 8f 5d }

  condition:
    any of them
}