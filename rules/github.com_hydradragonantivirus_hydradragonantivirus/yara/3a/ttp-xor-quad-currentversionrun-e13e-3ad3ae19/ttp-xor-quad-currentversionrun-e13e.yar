rule TTP_XOR_QUAD_CurrentVersionRun_e13e {
  strings:
    $key_e13e = { b2 51 [2] 96 5f [2] bd 73 [2] 93 51 [2] 87 4a [2] 88 50 [2] 96 4d [2] 94 4c [2] 8f 4a [2] 93 4d [2] 8f 62 }

  condition:
    any of them
}