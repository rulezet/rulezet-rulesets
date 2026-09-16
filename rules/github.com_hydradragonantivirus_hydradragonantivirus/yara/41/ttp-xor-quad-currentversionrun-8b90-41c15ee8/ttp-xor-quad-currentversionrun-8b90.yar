rule TTP_XOR_QUAD_CurrentVersionRun_8b90 {
  strings:
    $key_8b90 = { d8 ff [2] fc f1 [2] d7 dd [2] f9 ff [2] ed e4 [2] e2 fe [2] fc e3 [2] fe e2 [2] e5 e4 [2] f9 e3 [2] e5 cc }

  condition:
    any of them
}