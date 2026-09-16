rule TTP_XOR_QUAD_CurrentVersionRun_883a {
  strings:
    $key_883a = { db 55 [2] ff 5b [2] d4 77 [2] fa 55 [2] ee 4e [2] e1 54 [2] ff 49 [2] fd 48 [2] e6 4e [2] fa 49 [2] e6 66 }

  condition:
    any of them
}