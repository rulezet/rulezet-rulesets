rule TTP_XOR_MULT_DOSStub_c989 {
  strings:
    $key_c989 = { 9d e1 [2] e9 f9 [2] ae fb [2] e9 ea [2] a7 e6 [2] ab ec [2] bc e7 [2] a7 a9 [2] 9a }

  condition:
    any of them
}