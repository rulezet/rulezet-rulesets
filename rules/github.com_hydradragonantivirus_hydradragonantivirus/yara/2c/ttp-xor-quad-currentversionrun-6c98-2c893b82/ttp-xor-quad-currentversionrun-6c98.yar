rule TTP_XOR_QUAD_CurrentVersionRun_6c98 {
  strings:
    $key_6c98 = { 3f f7 [2] 1b f9 [2] 30 d5 [2] 1e f7 [2] 0a ec [2] 05 f6 [2] 1b eb [2] 19 ea [2] 02 ec [2] 1e eb [2] 02 c4 }

  condition:
    any of them
}