rule TTP_XOR_QUAD_CurrentVersionRun_882b {
  strings:
    $key_882b = { db 44 [2] ff 4a [2] d4 66 [2] fa 44 [2] ee 5f [2] e1 45 [2] ff 58 [2] fd 59 [2] e6 5f [2] fa 58 [2] e6 77 }

  condition:
    any of them
}