rule TTP_XOR_QUAD_CurrentVersionRun_499f {
  strings:
    $key_499f = { 1a f0 [2] 3e fe [2] 15 d2 [2] 3b f0 [2] 2f eb [2] 20 f1 [2] 3e ec [2] 3c ed [2] 27 eb [2] 3b ec [2] 27 c3 }

  condition:
    any of them
}