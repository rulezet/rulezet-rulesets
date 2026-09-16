rule TTP_XOR_QUAD_CurrentVersionRun_b230 {
  strings:
    $key_b230 = { e1 5f [2] c5 51 [2] ee 7d [2] c0 5f [2] d4 44 [2] db 5e [2] c5 43 [2] c7 42 [2] dc 44 [2] c0 43 [2] dc 6c }

  condition:
    any of them
}