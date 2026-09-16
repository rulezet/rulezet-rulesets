rule TTP_XOR_QUAD_CurrentVersionRun_b24a {
  strings:
    $key_b24a = { e1 25 [2] c5 2b [2] ee 07 [2] c0 25 [2] d4 3e [2] db 24 [2] c5 39 [2] c7 38 [2] dc 3e [2] c0 39 [2] dc 16 }

  condition:
    any of them
}