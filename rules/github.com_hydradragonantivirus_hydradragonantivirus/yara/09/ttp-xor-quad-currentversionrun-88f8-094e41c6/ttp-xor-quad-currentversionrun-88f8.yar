rule TTP_XOR_QUAD_CurrentVersionRun_88f8 {
  strings:
    $key_88f8 = { db 97 [2] ff 99 [2] d4 b5 [2] fa 97 [2] ee 8c [2] e1 96 [2] ff 8b [2] fd 8a [2] e6 8c [2] fa 8b [2] e6 a4 }

  condition:
    any of them
}