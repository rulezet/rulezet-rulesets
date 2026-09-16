rule TTP_XOR_QUAD_CurrentVersionRun_8823 {
  strings:
    $key_8823 = { db 4c [2] ff 42 [2] d4 6e [2] fa 4c [2] ee 57 [2] e1 4d [2] ff 50 [2] fd 51 [2] e6 57 [2] fa 50 [2] e6 7f }

  condition:
    any of them
}