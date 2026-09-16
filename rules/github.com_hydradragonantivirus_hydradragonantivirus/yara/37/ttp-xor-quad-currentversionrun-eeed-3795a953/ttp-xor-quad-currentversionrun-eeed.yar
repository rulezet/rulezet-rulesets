rule TTP_XOR_QUAD_CurrentVersionRun_eeed {
  strings:
    $key_eeed = { bd 82 [2] 99 8c [2] b2 a0 [2] 9c 82 [2] 88 99 [2] 87 83 [2] 99 9e [2] 9b 9f [2] 80 99 [2] 9c 9e [2] 80 b1 }

  condition:
    any of them
}