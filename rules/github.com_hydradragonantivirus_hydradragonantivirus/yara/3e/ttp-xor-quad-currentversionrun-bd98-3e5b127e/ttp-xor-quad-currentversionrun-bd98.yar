rule TTP_XOR_QUAD_CurrentVersionRun_bd98 {
  strings:
    $key_bd98 = { ee f7 [2] ca f9 [2] e1 d5 [2] cf f7 [2] db ec [2] d4 f6 [2] ca eb [2] c8 ea [2] d3 ec [2] cf eb [2] d3 c4 }

  condition:
    any of them
}