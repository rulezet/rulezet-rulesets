rule TTP_XOR_QUAD_CurrentVersionRun_e126 {
  strings:
    $key_e126 = { b2 49 [2] 96 47 [2] bd 6b [2] 93 49 [2] 87 52 [2] 88 48 [2] 96 55 [2] 94 54 [2] 8f 52 [2] 93 55 [2] 8f 7a }

  condition:
    any of them
}