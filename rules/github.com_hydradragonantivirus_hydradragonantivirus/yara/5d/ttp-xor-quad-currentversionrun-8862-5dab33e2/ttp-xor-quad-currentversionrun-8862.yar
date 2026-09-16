rule TTP_XOR_QUAD_CurrentVersionRun_8862 {
  strings:
    $key_8862 = { db 0d [2] ff 03 [2] d4 2f [2] fa 0d [2] ee 16 [2] e1 0c [2] ff 11 [2] fd 10 [2] e6 16 [2] fa 11 [2] e6 3e }

  condition:
    any of them
}