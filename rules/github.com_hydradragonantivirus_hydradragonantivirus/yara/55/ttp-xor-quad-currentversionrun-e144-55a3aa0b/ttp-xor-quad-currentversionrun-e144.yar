rule TTP_XOR_QUAD_CurrentVersionRun_e144 {
  strings:
    $key_e144 = { b2 2b [2] 96 25 [2] bd 09 [2] 93 2b [2] 87 30 [2] 88 2a [2] 96 37 [2] 94 36 [2] 8f 30 [2] 93 37 [2] 8f 18 }

  condition:
    any of them
}