rule TTP_XOR_MULT_DOSStub_379a {
  strings:
    $key_379a = { 63 f2 [2] 17 ea [2] 50 e8 [2] 17 f9 [2] 59 f5 [2] 55 ff [2] 42 f4 [2] 59 ba [2] 64 }

  condition:
    any of them
}