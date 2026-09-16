rule TTP_XOR_QUAD_CurrentVersionRun_8850 {
  strings:
    $key_8850 = { db 3f [2] ff 31 [2] d4 1d [2] fa 3f [2] ee 24 [2] e1 3e [2] ff 23 [2] fd 22 [2] e6 24 [2] fa 23 [2] e6 0c }

  condition:
    any of them
}