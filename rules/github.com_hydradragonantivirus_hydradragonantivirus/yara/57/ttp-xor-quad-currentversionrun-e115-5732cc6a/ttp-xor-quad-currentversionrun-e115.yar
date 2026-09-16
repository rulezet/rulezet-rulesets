rule TTP_XOR_QUAD_CurrentVersionRun_e115 {
  strings:
    $key_e115 = { b2 7a [2] 96 74 [2] bd 58 [2] 93 7a [2] 87 61 [2] 88 7b [2] 96 66 [2] 94 67 [2] 8f 61 [2] 93 66 [2] 8f 49 }

  condition:
    any of them
}