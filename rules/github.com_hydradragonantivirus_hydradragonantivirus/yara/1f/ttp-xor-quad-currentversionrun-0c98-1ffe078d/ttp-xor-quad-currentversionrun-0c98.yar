rule TTP_XOR_QUAD_CurrentVersionRun_0c98 {
  strings:
    $key_0c98 = { 5f f7 [2] 7b f9 [2] 50 d5 [2] 7e f7 [2] 6a ec [2] 65 f6 [2] 7b eb [2] 79 ea [2] 62 ec [2] 7e eb [2] 62 c4 }

  condition:
    any of them
}