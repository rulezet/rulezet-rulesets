rule TTP_XOR_QUAD_CurrentVersionRun_319f {
  strings:
    $key_319f = { 62 f0 [2] 46 fe [2] 6d d2 [2] 43 f0 [2] 57 eb [2] 58 f1 [2] 46 ec [2] 44 ed [2] 5f eb [2] 43 ec [2] 5f c3 }

  condition:
    any of them
}