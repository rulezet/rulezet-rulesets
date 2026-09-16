rule TTP_XOR_QUAD_CurrentVersionRun_883f {
  strings:
    $key_883f = { db 50 [2] ff 5e [2] d4 72 [2] fa 50 [2] ee 4b [2] e1 51 [2] ff 4c [2] fd 4d [2] e6 4b [2] fa 4c [2] e6 63 }

  condition:
    any of them
}