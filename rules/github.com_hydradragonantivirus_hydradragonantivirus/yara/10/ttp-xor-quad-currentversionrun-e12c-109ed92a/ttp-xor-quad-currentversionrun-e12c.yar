rule TTP_XOR_QUAD_CurrentVersionRun_e12c {
  strings:
    $key_e12c = { b2 43 [2] 96 4d [2] bd 61 [2] 93 43 [2] 87 58 [2] 88 42 [2] 96 5f [2] 94 5e [2] 8f 58 [2] 93 5f [2] 8f 70 }

  condition:
    any of them
}