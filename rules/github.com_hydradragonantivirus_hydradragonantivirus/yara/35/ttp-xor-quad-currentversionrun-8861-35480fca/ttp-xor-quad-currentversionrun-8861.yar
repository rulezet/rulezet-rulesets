rule TTP_XOR_QUAD_CurrentVersionRun_8861 {
  strings:
    $key_8861 = { db 0e [2] ff 00 [2] d4 2c [2] fa 0e [2] ee 15 [2] e1 0f [2] ff 12 [2] fd 13 [2] e6 15 [2] fa 12 [2] e6 3d }

  condition:
    any of them
}