rule TTP_XOR_QUAD_CurrentVersionRun_3485 {
  strings:
    $key_3485 = { 67 ea [2] 43 e4 [2] 68 c8 [2] 46 ea [2] 52 f1 [2] 5d eb [2] 43 f6 [2] 41 f7 [2] 5a f1 [2] 46 f6 [2] 5a d9 }

  condition:
    any of them
}