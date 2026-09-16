rule TTP_XOR_QUAD_CurrentVersionRun_f998 {
  strings:
    $key_f998 = { aa f7 [2] 8e f9 [2] a5 d5 [2] 8b f7 [2] 9f ec [2] 90 f6 [2] 8e eb [2] 8c ea [2] 97 ec [2] 8b eb [2] 97 c4 }

  condition:
    any of them
}