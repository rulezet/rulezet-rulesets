rule TTP_XOR_QUAD_CurrentVersionRun_8eb3 {
  strings:
    $key_8eb3 = { dd dc [2] f9 d2 [2] d2 fe [2] fc dc [2] e8 c7 [2] e7 dd [2] f9 c0 [2] fb c1 [2] e0 c7 [2] fc c0 [2] e0 ef }

  condition:
    any of them
}