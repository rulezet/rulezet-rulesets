rule TTP_XOR_QUAD_CurrentVersionRun_887c {
  strings:
    $key_887c = { db 13 [2] ff 1d [2] d4 31 [2] fa 13 [2] ee 08 [2] e1 12 [2] ff 0f [2] fd 0e [2] e6 08 [2] fa 0f [2] e6 20 }

  condition:
    any of them
}