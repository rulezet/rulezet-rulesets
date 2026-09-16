rule TTP_XOR_MULT_DOSStub_1e94 {
  strings:
    $key_1e94 = { 4a fc [2] 3e e4 [2] 79 e6 [2] 3e f7 [2] 70 fb [2] 7c f1 [2] 6b fa [2] 70 b4 [2] 4d }

  condition:
    any of them
}