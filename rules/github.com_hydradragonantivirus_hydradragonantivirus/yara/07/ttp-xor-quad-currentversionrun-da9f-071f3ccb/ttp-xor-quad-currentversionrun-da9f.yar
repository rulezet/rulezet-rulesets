rule TTP_XOR_QUAD_CurrentVersionRun_da9f {
  strings:
    $key_da9f = { 89 f0 [2] ad fe [2] 86 d2 [2] a8 f0 [2] bc eb [2] b3 f1 [2] ad ec [2] af ed [2] b4 eb [2] a8 ec [2] b4 c3 }

  condition:
    any of them
}