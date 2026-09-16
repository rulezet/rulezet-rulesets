rule TTP_XOR_QUAD_CurrentVersionRun_884c {
  strings:
    $key_884c = { db 23 [2] ff 2d [2] d4 01 [2] fa 23 [2] ee 38 [2] e1 22 [2] ff 3f [2] fd 3e [2] e6 38 [2] fa 3f [2] e6 10 }

  condition:
    any of them
}