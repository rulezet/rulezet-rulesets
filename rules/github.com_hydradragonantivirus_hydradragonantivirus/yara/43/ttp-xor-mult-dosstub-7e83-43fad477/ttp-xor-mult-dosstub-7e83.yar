rule TTP_XOR_MULT_DOSStub_7e83 {
  strings:
    $key_7e83 = { 2a eb [2] 5e f3 [2] 19 f1 [2] 5e e0 [2] 10 ec [2] 1c e6 [2] 0b ed [2] 10 a3 [2] 2d }

  condition:
    any of them
}