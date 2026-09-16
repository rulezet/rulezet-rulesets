rule TTP_XOR_QUAD_CurrentVersionRun_88fd {
  strings:
    $key_88fd = { db 92 [2] ff 9c [2] d4 b0 [2] fa 92 [2] ee 89 [2] e1 93 [2] ff 8e [2] fd 8f [2] e6 89 [2] fa 8e [2] e6 a1 }

  condition:
    any of them
}