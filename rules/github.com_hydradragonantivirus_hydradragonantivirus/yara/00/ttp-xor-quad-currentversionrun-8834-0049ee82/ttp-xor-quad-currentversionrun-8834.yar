rule TTP_XOR_QUAD_CurrentVersionRun_8834 {
  strings:
    $key_8834 = { db 5b [2] ff 55 [2] d4 79 [2] fa 5b [2] ee 40 [2] e1 5a [2] ff 47 [2] fd 46 [2] e6 40 [2] fa 47 [2] e6 68 }

  condition:
    any of them
}