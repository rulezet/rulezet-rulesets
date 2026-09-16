rule TTP_XOR_QUAD_CurrentVersionRun_8875 {
  strings:
    $key_8875 = { db 1a [2] ff 14 [2] d4 38 [2] fa 1a [2] ee 01 [2] e1 1b [2] ff 06 [2] fd 07 [2] e6 01 [2] fa 06 [2] e6 29 }

  condition:
    any of them
}