rule TTP_XOR_QUAD_CurrentVersionRun_8876 {
  strings:
    $key_8876 = { db 19 [2] ff 17 [2] d4 3b [2] fa 19 [2] ee 02 [2] e1 18 [2] ff 05 [2] fd 04 [2] e6 02 [2] fa 05 [2] e6 2a }

  condition:
    any of them
}