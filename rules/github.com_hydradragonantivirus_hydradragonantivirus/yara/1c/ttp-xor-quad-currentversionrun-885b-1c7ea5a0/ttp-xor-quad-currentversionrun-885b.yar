rule TTP_XOR_QUAD_CurrentVersionRun_885b {
  strings:
    $key_885b = { db 34 [2] ff 3a [2] d4 16 [2] fa 34 [2] ee 2f [2] e1 35 [2] ff 28 [2] fd 29 [2] e6 2f [2] fa 28 [2] e6 07 }

  condition:
    any of them
}