rule TTP_XOR_QUAD_CurrentVersionRun_8831 {
  strings:
    $key_8831 = { db 5e [2] ff 50 [2] d4 7c [2] fa 5e [2] ee 45 [2] e1 5f [2] ff 42 [2] fd 43 [2] e6 45 [2] fa 42 [2] e6 6d }

  condition:
    any of them
}