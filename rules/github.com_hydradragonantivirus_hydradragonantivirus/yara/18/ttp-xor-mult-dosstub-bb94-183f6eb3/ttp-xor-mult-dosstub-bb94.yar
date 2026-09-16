rule TTP_XOR_MULT_DOSStub_bb94 {
  strings:
    $key_bb94 = { ef fc [2] 9b e4 [2] dc e6 [2] 9b f7 [2] d5 fb [2] d9 f1 [2] ce fa [2] d5 b4 [2] e8 }

  condition:
    any of them
}