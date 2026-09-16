rule TTP_XOR_MULT_DOSStub_4e83 {
  strings:
    $key_4e83 = { 1a eb [2] 6e f3 [2] 29 f1 [2] 6e e0 [2] 20 ec [2] 2c e6 [2] 3b ed [2] 20 a3 [2] 1d }

  condition:
    any of them
}