rule TTP_XOR_MULT_DOSStub_679c {
  strings:
    $key_679c = { 33 f4 [2] 47 ec [2] 00 ee [2] 47 ff [2] 09 f3 [2] 05 f9 [2] 12 f2 [2] 09 bc [2] 34 }

  condition:
    any of them
}