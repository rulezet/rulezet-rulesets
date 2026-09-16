rule TTP_XOR_QUAD_CurrentVersionRun_b20d {
  strings:
    $key_b20d = { e1 62 [2] c5 6c [2] ee 40 [2] c0 62 [2] d4 79 [2] db 63 [2] c5 7e [2] c7 7f [2] dc 79 [2] c0 7e [2] dc 51 }

  condition:
    any of them
}