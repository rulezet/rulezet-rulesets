rule TTP_XOR_MULT_DOSStub_209c {
  strings:
    $key_209c = { 74 f4 [2] 00 ec [2] 47 ee [2] 00 ff [2] 4e f3 [2] 42 f9 [2] 55 f2 [2] 4e bc [2] 73 }

  condition:
    any of them
}