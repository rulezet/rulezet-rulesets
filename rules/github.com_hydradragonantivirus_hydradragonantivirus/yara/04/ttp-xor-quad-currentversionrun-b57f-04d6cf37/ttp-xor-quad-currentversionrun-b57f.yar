rule TTP_XOR_QUAD_CurrentVersionRun_b57f {
  strings:
    $key_b57f = { e6 10 [2] c2 1e [2] e9 32 [2] c7 10 [2] d3 0b [2] dc 11 [2] c2 0c [2] c0 0d [2] db 0b [2] c7 0c [2] db 23 }

  condition:
    any of them
}