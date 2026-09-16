rule TTP_XOR_QUAD_CurrentVersionRun_e10c {
  strings:
    $key_e10c = { b2 63 [2] 96 6d [2] bd 41 [2] 93 63 [2] 87 78 [2] 88 62 [2] 96 7f [2] 94 7e [2] 8f 78 [2] 93 7f [2] 8f 50 }

  condition:
    any of them
}