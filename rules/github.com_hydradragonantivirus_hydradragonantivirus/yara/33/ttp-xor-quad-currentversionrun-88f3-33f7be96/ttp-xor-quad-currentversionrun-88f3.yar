rule TTP_XOR_QUAD_CurrentVersionRun_88f3 {
  strings:
    $key_88f3 = { db 9c [2] ff 92 [2] d4 be [2] fa 9c [2] ee 87 [2] e1 9d [2] ff 80 [2] fd 81 [2] e6 87 [2] fa 80 [2] e6 af }

  condition:
    any of them
}