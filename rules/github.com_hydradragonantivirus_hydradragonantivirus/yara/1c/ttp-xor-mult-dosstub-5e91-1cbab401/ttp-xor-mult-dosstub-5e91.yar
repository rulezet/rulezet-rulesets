rule TTP_XOR_MULT_DOSStub_5e91 {
  strings:
    $key_5e91 = { 0a f9 [2] 7e e1 [2] 39 e3 [2] 7e f2 [2] 30 fe [2] 3c f4 [2] 2b ff [2] 30 b1 [2] 0d }

  condition:
    any of them
}