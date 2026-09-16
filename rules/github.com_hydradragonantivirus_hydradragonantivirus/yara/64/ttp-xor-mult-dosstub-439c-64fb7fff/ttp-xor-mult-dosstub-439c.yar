rule TTP_XOR_MULT_DOSStub_439c {
  strings:
    $key_439c = { 17 f4 [2] 63 ec [2] 24 ee [2] 63 ff [2] 2d f3 [2] 21 f9 [2] 36 f2 [2] 2d bc [2] 10 }

  condition:
    any of them
}