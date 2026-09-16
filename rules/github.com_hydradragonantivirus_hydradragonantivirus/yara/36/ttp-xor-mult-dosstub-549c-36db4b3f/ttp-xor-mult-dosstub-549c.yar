rule TTP_XOR_MULT_DOSStub_549c {
  strings:
    $key_549c = { 00 f4 [2] 74 ec [2] 33 ee [2] 74 ff [2] 3a f3 [2] 36 f9 [2] 21 f2 [2] 3a bc [2] 07 }

  condition:
    any of them
}