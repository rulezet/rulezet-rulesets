rule TTP_XOR_MULT_DOSStub_529c {
  strings:
    $key_529c = { 06 f4 [2] 72 ec [2] 35 ee [2] 72 ff [2] 3c f3 [2] 30 f9 [2] 27 f2 [2] 3c bc [2] 01 }

  condition:
    any of them
}