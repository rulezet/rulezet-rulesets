rule TTP_XOR_QUAD_CurrentVersionRun_880f {
  strings:
    $key_880f = { db 60 [2] ff 6e [2] d4 42 [2] fa 60 [2] ee 7b [2] e1 61 [2] ff 7c [2] fd 7d [2] e6 7b [2] fa 7c [2] e6 53 }

  condition:
    any of them
}