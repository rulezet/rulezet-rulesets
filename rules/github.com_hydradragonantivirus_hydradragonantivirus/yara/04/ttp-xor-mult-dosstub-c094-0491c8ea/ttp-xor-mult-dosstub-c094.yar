rule TTP_XOR_MULT_DOSStub_c094 {
  strings:
    $key_c094 = { 94 fc [2] e0 e4 [2] a7 e6 [2] e0 f7 [2] ae fb [2] a2 f1 [2] b5 fa [2] ae b4 [2] 93 }

  condition:
    any of them
}