rule TTP_XOR_QUAD_CurrentVersionRun_e1c5 {
  strings:
    $key_e1c5 = { b2 aa [2] 96 a4 [2] bd 88 [2] 93 aa [2] 87 b1 [2] 88 ab [2] 96 b6 [2] 94 b7 [2] 8f b1 [2] 93 b6 [2] 8f 99 }

  condition:
    any of them
}