rule TTP_XOR_QUAD_CurrentVersionRun_88e4 {
  strings:
    $key_88e4 = { db 8b [2] ff 85 [2] d4 a9 [2] fa 8b [2] ee 90 [2] e1 8a [2] ff 97 [2] fd 96 [2] e6 90 [2] fa 97 [2] e6 b8 }

  condition:
    any of them
}