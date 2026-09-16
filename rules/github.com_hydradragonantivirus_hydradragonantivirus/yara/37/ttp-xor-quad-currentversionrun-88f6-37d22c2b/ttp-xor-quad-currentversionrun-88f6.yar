rule TTP_XOR_QUAD_CurrentVersionRun_88f6 {
  strings:
    $key_88f6 = { db 99 [2] ff 97 [2] d4 bb [2] fa 99 [2] ee 82 [2] e1 98 [2] ff 85 [2] fd 84 [2] e6 82 [2] fa 85 [2] e6 aa }

  condition:
    any of them
}