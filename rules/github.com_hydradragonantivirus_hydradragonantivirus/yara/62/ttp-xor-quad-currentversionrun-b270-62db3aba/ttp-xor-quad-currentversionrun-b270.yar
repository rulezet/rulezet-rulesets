rule TTP_XOR_QUAD_CurrentVersionRun_b270 {
  strings:
    $key_b270 = { e1 1f [2] c5 11 [2] ee 3d [2] c0 1f [2] d4 04 [2] db 1e [2] c5 03 [2] c7 02 [2] dc 04 [2] c0 03 [2] dc 2c }

  condition:
    any of them
}