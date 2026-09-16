rule TTP_XOR_QUAD_CurrentVersionRun_88fc {
  strings:
    $key_88fc = { db 93 [2] ff 9d [2] d4 b1 [2] fa 93 [2] ee 88 [2] e1 92 [2] ff 8f [2] fd 8e [2] e6 88 [2] fa 8f [2] e6 a0 }

  condition:
    any of them
}