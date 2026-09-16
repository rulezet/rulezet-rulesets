rule TTP_XOR_QUAD_CurrentVersionRun_2885 {
  strings:
    $key_2885 = { 7b ea [2] 5f e4 [2] 74 c8 [2] 5a ea [2] 4e f1 [2] 41 eb [2] 5f f6 [2] 5d f7 [2] 46 f1 [2] 5a f6 [2] 46 d9 }

  condition:
    any of them
}