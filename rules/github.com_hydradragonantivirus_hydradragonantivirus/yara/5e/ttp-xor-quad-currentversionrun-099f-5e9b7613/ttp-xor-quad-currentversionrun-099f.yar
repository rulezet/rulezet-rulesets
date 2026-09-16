rule TTP_XOR_QUAD_CurrentVersionRun_099f {
  strings:
    $key_099f = { 5a f0 [2] 7e fe [2] 55 d2 [2] 7b f0 [2] 6f eb [2] 60 f1 [2] 7e ec [2] 7c ed [2] 67 eb [2] 7b ec [2] 67 c3 }

  condition:
    any of them
}