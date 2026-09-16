rule TTP_XOR_QUAD_CurrentVersionRun_88ab {
  strings:
    $key_88ab = { db c4 [2] ff ca [2] d4 e6 [2] fa c4 [2] ee df [2] e1 c5 [2] ff d8 [2] fd d9 [2] e6 df [2] fa d8 [2] e6 f7 }

  condition:
    any of them
}