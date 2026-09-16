rule TTP_XOR_QUAD_CurrentVersionRun_6998 {
  strings:
    $key_6998 = { 3a f7 [2] 1e f9 [2] 35 d5 [2] 1b f7 [2] 0f ec [2] 00 f6 [2] 1e eb [2] 1c ea [2] 07 ec [2] 1b eb [2] 07 c4 }

  condition:
    any of them
}