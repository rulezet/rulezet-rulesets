rule TTP_XOR_MULT_DOSStub_519a {
  strings:
    $key_519a = { 05 f2 [2] 71 ea [2] 36 e8 [2] 71 f9 [2] 3f f5 [2] 33 ff [2] 24 f4 [2] 3f ba [2] 02 }

  condition:
    any of them
}