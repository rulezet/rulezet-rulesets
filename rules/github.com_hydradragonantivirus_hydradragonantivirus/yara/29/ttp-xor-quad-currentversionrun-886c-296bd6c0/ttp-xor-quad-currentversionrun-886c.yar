rule TTP_XOR_QUAD_CurrentVersionRun_886c {
  strings:
    $key_886c = { db 03 [2] ff 0d [2] d4 21 [2] fa 03 [2] ee 18 [2] e1 02 [2] ff 1f [2] fd 1e [2] e6 18 [2] fa 1f [2] e6 30 }

  condition:
    any of them
}