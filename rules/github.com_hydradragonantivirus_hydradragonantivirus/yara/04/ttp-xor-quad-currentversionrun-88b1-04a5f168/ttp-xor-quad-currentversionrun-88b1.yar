rule TTP_XOR_QUAD_CurrentVersionRun_88b1 {
  strings:
    $key_88b1 = { db de [2] ff d0 [2] d4 fc [2] fa de [2] ee c5 [2] e1 df [2] ff c2 [2] fd c3 [2] e6 c5 [2] fa c2 [2] e6 ed }

  condition:
    any of them
}