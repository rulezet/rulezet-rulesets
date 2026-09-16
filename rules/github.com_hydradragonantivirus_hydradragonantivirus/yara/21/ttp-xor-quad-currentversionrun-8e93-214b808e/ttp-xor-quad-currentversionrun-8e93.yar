rule TTP_XOR_QUAD_CurrentVersionRun_8e93 {
  strings:
    $key_8e93 = { dd fc [2] f9 f2 [2] d2 de [2] fc fc [2] e8 e7 [2] e7 fd [2] f9 e0 [2] fb e1 [2] e0 e7 [2] fc e0 [2] e0 cf }

  condition:
    any of them
}