rule TTP_XOR_QUAD_CurrentVersionRun_88fe {
  strings:
    $key_88fe = { db 91 [2] ff 9f [2] d4 b3 [2] fa 91 [2] ee 8a [2] e1 90 [2] ff 8d [2] fd 8c [2] e6 8a [2] fa 8d [2] e6 a2 }

  condition:
    any of them
}