rule TTP_XOR_QUAD_CurrentVersionRun_88ff {
  strings:
    $key_88ff = { db 90 [2] ff 9e [2] d4 b2 [2] fa 90 [2] ee 8b [2] e1 91 [2] ff 8c [2] fd 8d [2] e6 8b [2] fa 8c [2] e6 a3 }

  condition:
    any of them
}