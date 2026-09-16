rule TTP_XOR_QUAD_CurrentVersionRun_8822 {
  strings:
    $key_8822 = { db 4d [2] ff 43 [2] d4 6f [2] fa 4d [2] ee 56 [2] e1 4c [2] ff 51 [2] fd 50 [2] e6 56 [2] fa 51 [2] e6 7e }

  condition:
    any of them
}