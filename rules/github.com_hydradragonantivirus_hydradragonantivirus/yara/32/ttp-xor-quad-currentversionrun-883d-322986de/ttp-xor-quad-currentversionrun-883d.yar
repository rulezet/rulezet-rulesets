rule TTP_XOR_QUAD_CurrentVersionRun_883d {
  strings:
    $key_883d = { db 52 [2] ff 5c [2] d4 70 [2] fa 52 [2] ee 49 [2] e1 53 [2] ff 4e [2] fd 4f [2] e6 49 [2] fa 4e [2] e6 61 }

  condition:
    any of them
}