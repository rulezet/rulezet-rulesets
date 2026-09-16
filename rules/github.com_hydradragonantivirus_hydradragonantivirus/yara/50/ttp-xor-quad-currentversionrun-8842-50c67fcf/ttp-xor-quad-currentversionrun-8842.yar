rule TTP_XOR_QUAD_CurrentVersionRun_8842 {
  strings:
    $key_8842 = { db 2d [2] ff 23 [2] d4 0f [2] fa 2d [2] ee 36 [2] e1 2c [2] ff 31 [2] fd 30 [2] e6 36 [2] fa 31 [2] e6 1e }

  condition:
    any of them
}