rule TTP_XOR_QUAD_CurrentVersionRun_359f {
  strings:
    $key_359f = { 66 f0 [2] 42 fe [2] 69 d2 [2] 47 f0 [2] 53 eb [2] 5c f1 [2] 42 ec [2] 40 ed [2] 5b eb [2] 47 ec [2] 5b c3 }

  condition:
    any of them
}