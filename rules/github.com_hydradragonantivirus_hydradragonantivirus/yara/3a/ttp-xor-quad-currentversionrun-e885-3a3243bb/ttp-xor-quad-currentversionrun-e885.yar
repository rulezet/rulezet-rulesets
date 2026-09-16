rule TTP_XOR_QUAD_CurrentVersionRun_e885 {
  strings:
    $key_e885 = { bb ea [2] 9f e4 [2] b4 c8 [2] 9a ea [2] 8e f1 [2] 81 eb [2] 9f f6 [2] 9d f7 [2] 86 f1 [2] 9a f6 [2] 86 d9 }

  condition:
    any of them
}