rule TTP_XOR_QUAD_CurrentVersionRun_887b {
  strings:
    $key_887b = { db 14 [2] ff 1a [2] d4 36 [2] fa 14 [2] ee 0f [2] e1 15 [2] ff 08 [2] fd 09 [2] e6 0f [2] fa 08 [2] e6 27 }

  condition:
    any of them
}