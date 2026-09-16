rule TTP_XOR_QUAD_CurrentVersionRun_8863 {
  strings:
    $key_8863 = { db 0c [2] ff 02 [2] d4 2e [2] fa 0c [2] ee 17 [2] e1 0d [2] ff 10 [2] fd 11 [2] e6 17 [2] fa 10 [2] e6 3f }

  condition:
    any of them
}