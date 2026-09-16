rule TTP_XOR_QUAD_CurrentVersionRun_349f {
  strings:
    $key_349f = { 67 f0 [2] 43 fe [2] 68 d2 [2] 46 f0 [2] 52 eb [2] 5d f1 [2] 43 ec [2] 41 ed [2] 5a eb [2] 46 ec [2] 5a c3 }

  condition:
    any of them
}