rule TTP_XOR_QUAD_CurrentVersionRun_8849 {
  strings:
    $key_8849 = { db 26 [2] ff 28 [2] d4 04 [2] fa 26 [2] ee 3d [2] e1 27 [2] ff 3a [2] fd 3b [2] e6 3d [2] fa 3a [2] e6 15 }

  condition:
    any of them
}