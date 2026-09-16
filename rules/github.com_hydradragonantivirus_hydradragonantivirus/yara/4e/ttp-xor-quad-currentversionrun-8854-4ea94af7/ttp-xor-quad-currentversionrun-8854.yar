rule TTP_XOR_QUAD_CurrentVersionRun_8854 {
  strings:
    $key_8854 = { db 3b [2] ff 35 [2] d4 19 [2] fa 3b [2] ee 20 [2] e1 3a [2] ff 27 [2] fd 26 [2] e6 20 [2] fa 27 [2] e6 08 }

  condition:
    any of them
}