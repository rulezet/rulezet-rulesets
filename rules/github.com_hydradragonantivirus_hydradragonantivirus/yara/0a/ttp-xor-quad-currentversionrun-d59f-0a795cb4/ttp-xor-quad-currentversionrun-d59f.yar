rule TTP_XOR_QUAD_CurrentVersionRun_d59f {
  strings:
    $key_d59f = { 86 f0 [2] a2 fe [2] 89 d2 [2] a7 f0 [2] b3 eb [2] bc f1 [2] a2 ec [2] a0 ed [2] bb eb [2] a7 ec [2] bb c3 }

  condition:
    any of them
}