rule TTP_XOR_QUAD_CurrentVersionRun_88e7 {
  strings:
    $key_88e7 = { db 88 [2] ff 86 [2] d4 aa [2] fa 88 [2] ee 93 [2] e1 89 [2] ff 94 [2] fd 95 [2] e6 93 [2] fa 94 [2] e6 bb }

  condition:
    any of them
}