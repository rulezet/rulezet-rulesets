rule TTP_XOR_QUAD_CurrentVersionRun_b56e {
  strings:
    $key_b56e = { e6 01 [2] c2 0f [2] e9 23 [2] c7 01 [2] d3 1a [2] dc 00 [2] c2 1d [2] c0 1c [2] db 1a [2] c7 1d [2] db 32 }

  condition:
    any of them
}