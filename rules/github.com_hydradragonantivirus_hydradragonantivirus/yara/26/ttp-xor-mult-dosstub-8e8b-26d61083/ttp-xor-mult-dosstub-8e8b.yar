rule TTP_XOR_MULT_DOSStub_8e8b {
  strings:
    $key_8e8b = { da e3 [2] ae fb [2] e9 f9 [2] ae e8 [2] e0 e4 [2] ec ee [2] fb e5 [2] e0 ab [2] dd }

  condition:
    any of them
}