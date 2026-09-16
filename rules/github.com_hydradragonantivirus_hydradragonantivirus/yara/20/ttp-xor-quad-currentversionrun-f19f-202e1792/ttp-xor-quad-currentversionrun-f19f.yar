rule TTP_XOR_QUAD_CurrentVersionRun_f19f {
  strings:
    $key_f19f = { a2 f0 [2] 86 fe [2] ad d2 [2] 83 f0 [2] 97 eb [2] 98 f1 [2] 86 ec [2] 84 ed [2] 9f eb [2] 83 ec [2] 9f c3 }

  condition:
    any of them
}