rule TTP_XOR_QUAD_CurrentVersionRun_888f {
  strings:
    $key_888f = { db e0 [2] ff ee [2] d4 c2 [2] fa e0 [2] ee fb [2] e1 e1 [2] ff fc [2] fd fd [2] e6 fb [2] fa fc [2] e6 d3 }

  condition:
    any of them
}