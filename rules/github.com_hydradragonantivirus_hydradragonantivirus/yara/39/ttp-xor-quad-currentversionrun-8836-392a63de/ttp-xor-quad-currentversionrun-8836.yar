rule TTP_XOR_QUAD_CurrentVersionRun_8836 {
  strings:
    $key_8836 = { db 59 [2] ff 57 [2] d4 7b [2] fa 59 [2] ee 42 [2] e1 58 [2] ff 45 [2] fd 44 [2] e6 42 [2] fa 45 [2] e6 6a }

  condition:
    any of them
}