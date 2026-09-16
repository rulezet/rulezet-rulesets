rule TTP_XOR_QUAD_CurrentVersionRun_8841 {
  strings:
    $key_8841 = { db 2e [2] ff 20 [2] d4 0c [2] fa 2e [2] ee 35 [2] e1 2f [2] ff 32 [2] fd 33 [2] e6 35 [2] fa 32 [2] e6 1d }

  condition:
    any of them
}