rule TTP_XOR_MULT_DOSStub_639c {
  strings:
    $key_639c = { 37 f4 [2] 43 ec [2] 04 ee [2] 43 ff [2] 0d f3 [2] 01 f9 [2] 16 f2 [2] 0d bc [2] 30 }

  condition:
    any of them
}