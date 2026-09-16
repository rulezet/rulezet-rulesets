rule TTP_XOR_QUAD_CurrentVersionRun_8828 {
  strings:
    $key_8828 = { db 47 [2] ff 49 [2] d4 65 [2] fa 47 [2] ee 5c [2] e1 46 [2] ff 5b [2] fd 5a [2] e6 5c [2] fa 5b [2] e6 74 }

  condition:
    any of them
}