rule TTP_XOR_QUAD_CurrentVersionRun_8e90 {
  strings:
    $key_8e90 = { dd ff [2] f9 f1 [2] d2 dd [2] fc ff [2] e8 e4 [2] e7 fe [2] f9 e3 [2] fb e2 [2] e0 e4 [2] fc e3 [2] e0 cc }

  condition:
    any of them
}