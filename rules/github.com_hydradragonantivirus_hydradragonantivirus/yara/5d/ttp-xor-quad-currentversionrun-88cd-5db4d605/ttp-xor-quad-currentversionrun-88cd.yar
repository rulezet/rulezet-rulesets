rule TTP_XOR_QUAD_CurrentVersionRun_88cd {
  strings:
    $key_88cd = { db a2 [2] ff ac [2] d4 80 [2] fa a2 [2] ee b9 [2] e1 a3 [2] ff be [2] fd bf [2] e6 b9 [2] fa be [2] e6 91 }

  condition:
    any of them
}