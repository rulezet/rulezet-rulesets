rule TTP_XOR_QUAD_CurrentVersionRun_88f9 {
  strings:
    $key_88f9 = { db 96 [2] ff 98 [2] d4 b4 [2] fa 96 [2] ee 8d [2] e1 97 [2] ff 8a [2] fd 8b [2] e6 8d [2] fa 8a [2] e6 a5 }

  condition:
    any of them
}