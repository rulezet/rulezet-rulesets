rule TTP_XOR_QUAD_CurrentVersionRun_884e {
  strings:
    $key_884e = { db 21 [2] ff 2f [2] d4 03 [2] fa 21 [2] ee 3a [2] e1 20 [2] ff 3d [2] fd 3c [2] e6 3a [2] fa 3d [2] e6 12 }

  condition:
    any of them
}