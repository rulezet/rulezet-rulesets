rule TTP_XOR_QUAD_CurrentVersionRun_b20a {
  strings:
    $key_b20a = { e1 65 [2] c5 6b [2] ee 47 [2] c0 65 [2] d4 7e [2] db 64 [2] c5 79 [2] c7 78 [2] dc 7e [2] c0 79 [2] dc 56 }

  condition:
    any of them
}