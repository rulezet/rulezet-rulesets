rule TTP_XOR_QUAD_CurrentVersionRun_885f {
  strings:
    $key_885f = { db 30 [2] ff 3e [2] d4 12 [2] fa 30 [2] ee 2b [2] e1 31 [2] ff 2c [2] fd 2d [2] e6 2b [2] fa 2c [2] e6 03 }

  condition:
    any of them
}