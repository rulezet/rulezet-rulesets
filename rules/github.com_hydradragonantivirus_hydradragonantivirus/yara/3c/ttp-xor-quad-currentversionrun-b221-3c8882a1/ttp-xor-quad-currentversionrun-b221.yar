rule TTP_XOR_QUAD_CurrentVersionRun_b221 {
  strings:
    $key_b221 = { e1 4e [2] c5 40 [2] ee 6c [2] c0 4e [2] d4 55 [2] db 4f [2] c5 52 [2] c7 53 [2] dc 55 [2] c0 52 [2] dc 7d }

  condition:
    any of them
}