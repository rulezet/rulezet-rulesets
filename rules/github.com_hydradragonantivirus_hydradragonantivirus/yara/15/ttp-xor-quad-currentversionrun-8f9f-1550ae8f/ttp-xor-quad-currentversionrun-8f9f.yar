rule TTP_XOR_QUAD_CurrentVersionRun_8f9f {
  strings:
    $key_8f9f = { dc f0 [2] f8 fe [2] d3 d2 [2] fd f0 [2] e9 eb [2] e6 f1 [2] f8 ec [2] fa ed [2] e1 eb [2] fd ec [2] e1 c3 }

  condition:
    any of them
}