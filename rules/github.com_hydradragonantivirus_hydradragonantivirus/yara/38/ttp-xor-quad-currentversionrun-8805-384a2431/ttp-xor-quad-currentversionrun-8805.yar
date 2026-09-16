rule TTP_XOR_QUAD_CurrentVersionRun_8805 {
  strings:
    $key_8805 = { db 6a [2] ff 64 [2] d4 48 [2] fa 6a [2] ee 71 [2] e1 6b [2] ff 76 [2] fd 77 [2] e6 71 [2] fa 76 [2] e6 59 }

  condition:
    any of them
}