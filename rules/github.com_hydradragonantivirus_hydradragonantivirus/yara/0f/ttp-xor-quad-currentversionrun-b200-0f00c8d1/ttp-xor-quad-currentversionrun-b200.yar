rule TTP_XOR_QUAD_CurrentVersionRun_b200 {
  strings:
    $key_b200 = { e1 6f [2] c5 61 [2] ee 4d [2] c0 6f [2] d4 74 [2] db 6e [2] c5 73 [2] c7 72 [2] dc 74 [2] c0 73 [2] dc 5c }

  condition:
    any of them
}