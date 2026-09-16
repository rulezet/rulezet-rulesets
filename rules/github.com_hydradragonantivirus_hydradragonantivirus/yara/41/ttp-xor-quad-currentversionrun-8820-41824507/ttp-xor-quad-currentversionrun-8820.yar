rule TTP_XOR_QUAD_CurrentVersionRun_8820 {
  strings:
    $key_8820 = { db 4f [2] ff 41 [2] d4 6d [2] fa 4f [2] ee 54 [2] e1 4e [2] ff 53 [2] fd 52 [2] e6 54 [2] fa 53 [2] e6 7c }

  condition:
    any of them
}