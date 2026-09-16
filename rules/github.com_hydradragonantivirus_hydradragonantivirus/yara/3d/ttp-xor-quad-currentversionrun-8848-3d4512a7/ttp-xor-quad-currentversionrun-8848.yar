rule TTP_XOR_QUAD_CurrentVersionRun_8848 {
  strings:
    $key_8848 = { db 27 [2] ff 29 [2] d4 05 [2] fa 27 [2] ee 3c [2] e1 26 [2] ff 3b [2] fd 3a [2] e6 3c [2] fa 3b [2] e6 14 }

  condition:
    any of them
}