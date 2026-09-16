rule TTP_XOR_QUAD_CurrentVersionRun_8867 {
  strings:
    $key_8867 = { db 08 [2] ff 06 [2] d4 2a [2] fa 08 [2] ee 13 [2] e1 09 [2] ff 14 [2] fd 15 [2] e6 13 [2] fa 14 [2] e6 3b }

  condition:
    any of them
}