rule TTP_XOR_QUAD_CurrentVersionRun_88a2 {
  strings:
    $key_88a2 = { db cd [2] ff c3 [2] d4 ef [2] fa cd [2] ee d6 [2] e1 cc [2] ff d1 [2] fd d0 [2] e6 d6 [2] fa d1 [2] e6 fe }

  condition:
    any of them
}