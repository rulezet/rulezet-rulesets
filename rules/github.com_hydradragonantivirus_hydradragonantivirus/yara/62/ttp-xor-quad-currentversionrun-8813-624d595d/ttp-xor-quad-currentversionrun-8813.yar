rule TTP_XOR_QUAD_CurrentVersionRun_8813 {
  strings:
    $key_8813 = { db 7c [2] ff 72 [2] d4 5e [2] fa 7c [2] ee 67 [2] e1 7d [2] ff 60 [2] fd 61 [2] e6 67 [2] fa 60 [2] e6 4f }

  condition:
    any of them
}