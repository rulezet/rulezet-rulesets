rule TTP_XOR_QUAD_CurrentVersionRun_e12a {
  strings:
    $key_e12a = { b2 45 [2] 96 4b [2] bd 67 [2] 93 45 [2] 87 5e [2] 88 44 [2] 96 59 [2] 94 58 [2] 8f 5e [2] 93 59 [2] 8f 76 }

  condition:
    any of them
}