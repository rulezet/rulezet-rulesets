rule TTP_XOR_QUAD_CurrentVersionRun_88ea {
  strings:
    $key_88ea = { db 85 [2] ff 8b [2] d4 a7 [2] fa 85 [2] ee 9e [2] e1 84 [2] ff 99 [2] fd 98 [2] e6 9e [2] fa 99 [2] e6 b6 }

  condition:
    any of them
}