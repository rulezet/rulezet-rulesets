rule TTP_XOR_QUAD_CurrentVersionRun_8865 {
  strings:
    $key_8865 = { db 0a [2] ff 04 [2] d4 28 [2] fa 0a [2] ee 11 [2] e1 0b [2] ff 16 [2] fd 17 [2] e6 11 [2] fa 16 [2] e6 39 }

  condition:
    any of them
}