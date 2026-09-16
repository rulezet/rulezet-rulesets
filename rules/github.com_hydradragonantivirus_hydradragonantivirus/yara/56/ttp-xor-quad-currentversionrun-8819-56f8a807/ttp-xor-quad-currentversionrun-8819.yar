rule TTP_XOR_QUAD_CurrentVersionRun_8819 {
  strings:
    $key_8819 = { db 76 [2] ff 78 [2] d4 54 [2] fa 76 [2] ee 6d [2] e1 77 [2] ff 6a [2] fd 6b [2] e6 6d [2] fa 6a [2] e6 45 }

  condition:
    any of them
}