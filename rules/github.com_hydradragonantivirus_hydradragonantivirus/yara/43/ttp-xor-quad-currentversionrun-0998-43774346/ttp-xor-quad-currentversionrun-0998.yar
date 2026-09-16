rule TTP_XOR_QUAD_CurrentVersionRun_0998 {
  strings:
    $key_0998 = { 5a f7 [2] 7e f9 [2] 55 d5 [2] 7b f7 [2] 6f ec [2] 60 f6 [2] 7e eb [2] 7c ea [2] 67 ec [2] 7b eb [2] 67 c4 }

  condition:
    any of them
}