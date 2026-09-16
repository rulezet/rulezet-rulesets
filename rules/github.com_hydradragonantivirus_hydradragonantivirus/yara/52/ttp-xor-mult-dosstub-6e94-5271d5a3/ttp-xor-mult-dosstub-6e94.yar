rule TTP_XOR_MULT_DOSStub_6e94 {
  strings:
    $key_6e94 = { 3a fc [2] 4e e4 [2] 09 e6 [2] 4e f7 [2] 00 fb [2] 0c f1 [2] 1b fa [2] 00 b4 [2] 3d }

  condition:
    any of them
}