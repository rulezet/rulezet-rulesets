rule TTP_XOR_QUAD_CurrentVersionRun_880e {
  strings:
    $key_880e = { db 61 [2] ff 6f [2] d4 43 [2] fa 61 [2] ee 7a [2] e1 60 [2] ff 7d [2] fd 7c [2] e6 7a [2] fa 7d [2] e6 52 }

  condition:
    any of them
}