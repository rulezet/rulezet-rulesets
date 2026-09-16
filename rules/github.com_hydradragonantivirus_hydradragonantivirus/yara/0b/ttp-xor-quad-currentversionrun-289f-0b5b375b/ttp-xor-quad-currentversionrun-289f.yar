rule TTP_XOR_QUAD_CurrentVersionRun_289f {
  strings:
    $key_289f = { 7b f0 [2] 5f fe [2] 74 d2 [2] 5a f0 [2] 4e eb [2] 41 f1 [2] 5f ec [2] 5d ed [2] 46 eb [2] 5a ec [2] 46 c3 }

  condition:
    any of them
}