rule TTP_XOR_MULT_DOSStub_7e91 {
  strings:
    $key_7e91 = { 2a f9 [2] 5e e1 [2] 19 e3 [2] 5e f2 [2] 10 fe [2] 1c f4 [2] 0b ff [2] 10 b1 [2] 2d }

  condition:
    any of them
}