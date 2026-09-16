rule TTP_XOR_QUAD_CurrentVersionRun_1c98 {
  strings:
    $key_1c98 = { 4f f7 [2] 6b f9 [2] 40 d5 [2] 6e f7 [2] 7a ec [2] 75 f6 [2] 6b eb [2] 69 ea [2] 72 ec [2] 6e eb [2] 72 c4 }

  condition:
    any of them
}