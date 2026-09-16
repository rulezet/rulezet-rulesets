rule TTP_XOR_QUAD_CurrentVersionRun_159f {
  strings:
    $key_159f = { 46 f0 [2] 62 fe [2] 49 d2 [2] 67 f0 [2] 73 eb [2] 7c f1 [2] 62 ec [2] 60 ed [2] 7b eb [2] 67 ec [2] 7b c3 }

  condition:
    any of them
}