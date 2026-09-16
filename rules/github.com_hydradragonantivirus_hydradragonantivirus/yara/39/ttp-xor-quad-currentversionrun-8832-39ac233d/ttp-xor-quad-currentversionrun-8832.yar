rule TTP_XOR_QUAD_CurrentVersionRun_8832 {
  strings:
    $key_8832 = { db 5d [2] ff 53 [2] d4 7f [2] fa 5d [2] ee 46 [2] e1 5c [2] ff 41 [2] fd 40 [2] e6 46 [2] fa 41 [2] e6 6e }

  condition:
    any of them
}