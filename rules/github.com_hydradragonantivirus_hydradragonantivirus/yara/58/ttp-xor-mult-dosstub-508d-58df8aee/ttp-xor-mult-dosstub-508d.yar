rule TTP_XOR_MULT_DOSStub_508d {
  strings:
    $key_508d = { 04 e5 [2] 70 fd [2] 37 ff [2] 70 ee [2] 3e e2 [2] 32 e8 [2] 25 e3 [2] 3e ad [2] 03 }

  condition:
    any of them
}