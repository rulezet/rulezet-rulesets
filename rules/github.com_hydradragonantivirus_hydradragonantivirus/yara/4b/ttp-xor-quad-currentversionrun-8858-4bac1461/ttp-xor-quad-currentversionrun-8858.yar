rule TTP_XOR_QUAD_CurrentVersionRun_8858 {
  strings:
    $key_8858 = { db 37 [2] ff 39 [2] d4 15 [2] fa 37 [2] ee 2c [2] e1 36 [2] ff 2b [2] fd 2a [2] e6 2c [2] fa 2b [2] e6 04 }

  condition:
    any of them
}