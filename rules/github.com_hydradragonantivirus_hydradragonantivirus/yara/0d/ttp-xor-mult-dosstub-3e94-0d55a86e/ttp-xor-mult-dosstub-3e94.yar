rule TTP_XOR_MULT_DOSStub_3e94 {
  strings:
    $key_3e94 = { 6a fc [2] 1e e4 [2] 59 e6 [2] 1e f7 [2] 50 fb [2] 5c f1 [2] 4b fa [2] 50 b4 [2] 6d }

  condition:
    any of them
}