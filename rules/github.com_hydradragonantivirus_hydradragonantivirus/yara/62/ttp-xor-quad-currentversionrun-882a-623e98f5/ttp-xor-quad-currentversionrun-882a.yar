rule TTP_XOR_QUAD_CurrentVersionRun_882a {
  strings:
    $key_882a = { db 45 [2] ff 4b [2] d4 67 [2] fa 45 [2] ee 5e [2] e1 44 [2] ff 59 [2] fd 58 [2] e6 5e [2] fa 59 [2] e6 76 }

  condition:
    any of them
}