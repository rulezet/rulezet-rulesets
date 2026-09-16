rule TTP_XOR_QUAD_CurrentVersionRun_e134 {
  strings:
    $key_e134 = { b2 5b [2] 96 55 [2] bd 79 [2] 93 5b [2] 87 40 [2] 88 5a [2] 96 47 [2] 94 46 [2] 8f 40 [2] 93 47 [2] 8f 68 }

  condition:
    any of them
}