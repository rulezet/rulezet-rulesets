rule TTP_XOR_QUAD_CurrentVersionRun_e138 {
  strings:
    $key_e138 = { b2 57 [2] 96 59 [2] bd 75 [2] 93 57 [2] 87 4c [2] 88 56 [2] 96 4b [2] 94 4a [2] 8f 4c [2] 93 4b [2] 8f 64 }

  condition:
    any of them
}