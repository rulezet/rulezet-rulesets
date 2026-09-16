rule TTP_XOR_QUAD_CurrentVersionRun_b24d {
  strings:
    $key_b24d = { e1 22 [2] c5 2c [2] ee 00 [2] c0 22 [2] d4 39 [2] db 23 [2] c5 3e [2] c7 3f [2] dc 39 [2] c0 3e [2] dc 11 }

  condition:
    any of them
}