rule TTP_XOR_QUAD_CurrentVersionRun_e158 {
  strings:
    $key_e158 = { b2 37 [2] 96 39 [2] bd 15 [2] 93 37 [2] 87 2c [2] 88 36 [2] 96 2b [2] 94 2a [2] 8f 2c [2] 93 2b [2] 8f 04 }

  condition:
    any of them
}