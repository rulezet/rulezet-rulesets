rule TTP_XOR_QUAD_CurrentVersionRun_8860 {
  strings:
    $key_8860 = { db 0f [2] ff 01 [2] d4 2d [2] fa 0f [2] ee 14 [2] e1 0e [2] ff 13 [2] fd 12 [2] e6 14 [2] fa 13 [2] e6 3c }

  condition:
    any of them
}