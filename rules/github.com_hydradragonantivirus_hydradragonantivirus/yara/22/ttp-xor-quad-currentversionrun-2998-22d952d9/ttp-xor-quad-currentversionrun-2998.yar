rule TTP_XOR_QUAD_CurrentVersionRun_2998 {
  strings:
    $key_2998 = { 7a f7 [2] 5e f9 [2] 75 d5 [2] 5b f7 [2] 4f ec [2] 40 f6 [2] 5e eb [2] 5c ea [2] 47 ec [2] 5b eb [2] 47 c4 }

  condition:
    any of them
}