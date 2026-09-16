rule TTP_XOR_QUAD_CurrentVersionRun_e17a {
  strings:
    $key_e17a = { b2 15 [2] 96 1b [2] bd 37 [2] 93 15 [2] 87 0e [2] 88 14 [2] 96 09 [2] 94 08 [2] 8f 0e [2] 93 09 [2] 8f 26 }

  condition:
    any of them
}