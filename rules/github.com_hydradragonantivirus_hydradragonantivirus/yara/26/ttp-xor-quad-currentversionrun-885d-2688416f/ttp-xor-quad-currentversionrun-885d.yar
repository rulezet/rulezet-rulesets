rule TTP_XOR_QUAD_CurrentVersionRun_885d {
  strings:
    $key_885d = { db 32 [2] ff 3c [2] d4 10 [2] fa 32 [2] ee 29 [2] e1 33 [2] ff 2e [2] fd 2f [2] e6 29 [2] fa 2e [2] e6 01 }

  condition:
    any of them
}