rule TTP_XOR_QUAD_CurrentVersionRun_e12b {
  strings:
    $key_e12b = { b2 44 [2] 96 4a [2] bd 66 [2] 93 44 [2] 87 5f [2] 88 45 [2] 96 58 [2] 94 59 [2] 8f 5f [2] 93 58 [2] 8f 77 }

  condition:
    any of them
}