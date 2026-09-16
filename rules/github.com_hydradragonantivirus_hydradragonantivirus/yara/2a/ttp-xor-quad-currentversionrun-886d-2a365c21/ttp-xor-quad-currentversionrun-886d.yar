rule TTP_XOR_QUAD_CurrentVersionRun_886d {
  strings:
    $key_886d = { db 02 [2] ff 0c [2] d4 20 [2] fa 02 [2] ee 19 [2] e1 03 [2] ff 1e [2] fd 1f [2] e6 19 [2] fa 1e [2] e6 31 }

  condition:
    any of them
}