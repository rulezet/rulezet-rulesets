rule TTP_XOR_QUAD_CurrentVersionRun_8c90 {
  strings:
    $key_8c90 = { df ff [2] fb f1 [2] d0 dd [2] fe ff [2] ea e4 [2] e5 fe [2] fb e3 [2] f9 e2 [2] e2 e4 [2] fe e3 [2] e2 cc }

  condition:
    any of them
}