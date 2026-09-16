rule TTP_XOR_QUAD_CurrentVersionRun_b27f {
  strings:
    $key_b27f = { e1 10 [2] c5 1e [2] ee 32 [2] c0 10 [2] d4 0b [2] db 11 [2] c5 0c [2] c7 0d [2] dc 0b [2] c0 0c [2] dc 23 }

  condition:
    any of them
}