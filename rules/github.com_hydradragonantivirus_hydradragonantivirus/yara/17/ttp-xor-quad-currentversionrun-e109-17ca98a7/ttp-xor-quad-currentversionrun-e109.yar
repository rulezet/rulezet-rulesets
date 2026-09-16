rule TTP_XOR_QUAD_CurrentVersionRun_e109 {
  strings:
    $key_e109 = { b2 66 [2] 96 68 [2] bd 44 [2] 93 66 [2] 87 7d [2] 88 67 [2] 96 7a [2] 94 7b [2] 8f 7d [2] 93 7a [2] 8f 55 }

  condition:
    any of them
}