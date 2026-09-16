rule TTP_XOR_QUAD_CurrentVersionRun_8826 {
  strings:
    $key_8826 = { db 49 [2] ff 47 [2] d4 6b [2] fa 49 [2] ee 52 [2] e1 48 [2] ff 55 [2] fd 54 [2] e6 52 [2] fa 55 [2] e6 7a }

  condition:
    any of them
}