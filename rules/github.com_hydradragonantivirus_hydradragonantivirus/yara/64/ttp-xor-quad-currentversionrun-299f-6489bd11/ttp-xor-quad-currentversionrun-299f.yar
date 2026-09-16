rule TTP_XOR_QUAD_CurrentVersionRun_299f {
  strings:
    $key_299f = { 7a f0 [2] 5e fe [2] 75 d2 [2] 5b f0 [2] 4f eb [2] 40 f1 [2] 5e ec [2] 5c ed [2] 47 eb [2] 5b ec [2] 47 c3 }

  condition:
    any of them
}