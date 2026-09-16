rule TTP_XOR_QUAD_CurrentVersionRun_e12f {
  strings:
    $key_e12f = { b2 40 [2] 96 4e [2] bd 62 [2] 93 40 [2] 87 5b [2] 88 41 [2] 96 5c [2] 94 5d [2] 8f 5b [2] 93 5c [2] 8f 73 }

  condition:
    any of them
}