rule TTP_XOR_QUAD_CurrentVersionRun_8818 {
  strings:
    $key_8818 = { db 77 [2] ff 79 [2] d4 55 [2] fa 77 [2] ee 6c [2] e1 76 [2] ff 6b [2] fd 6a [2] e6 6c [2] fa 6b [2] e6 44 }

  condition:
    any of them
}