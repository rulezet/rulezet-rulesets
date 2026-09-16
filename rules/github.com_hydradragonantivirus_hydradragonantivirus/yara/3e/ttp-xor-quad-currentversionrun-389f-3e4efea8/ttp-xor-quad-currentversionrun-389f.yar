rule TTP_XOR_QUAD_CurrentVersionRun_389f {
  strings:
    $key_389f = { 6b f0 [2] 4f fe [2] 64 d2 [2] 4a f0 [2] 5e eb [2] 51 f1 [2] 4f ec [2] 4d ed [2] 56 eb [2] 4a ec [2] 56 c3 }

  condition:
    any of them
}