rule TTP_XOR_QUAD_CurrentVersionRun_1998 {
  strings:
    $key_1998 = { 4a f7 [2] 6e f9 [2] 45 d5 [2] 6b f7 [2] 7f ec [2] 70 f6 [2] 6e eb [2] 6c ea [2] 77 ec [2] 6b eb [2] 77 c4 }

  condition:
    any of them
}