rule TTP_XOR_QUAD_CurrentVersionRun_88f0 {
  strings:
    $key_88f0 = { db 9f [2] ff 91 [2] d4 bd [2] fa 9f [2] ee 84 [2] e1 9e [2] ff 83 [2] fd 82 [2] e6 84 [2] fa 83 [2] e6 ac }

  condition:
    any of them
}