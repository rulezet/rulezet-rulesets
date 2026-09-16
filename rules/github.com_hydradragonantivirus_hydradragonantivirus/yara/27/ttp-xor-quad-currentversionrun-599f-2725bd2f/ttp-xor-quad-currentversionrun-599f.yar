rule TTP_XOR_QUAD_CurrentVersionRun_599f {
  strings:
    $key_599f = { 0a f0 [2] 2e fe [2] 05 d2 [2] 2b f0 [2] 3f eb [2] 30 f1 [2] 2e ec [2] 2c ed [2] 37 eb [2] 2b ec [2] 37 c3 }

  condition:
    any of them
}