rule TTP_XOR_MULT_DOSStub_f0da {
  strings:
    $key_f0da = { a4 b2 [2] d0 aa [2] 97 a8 [2] d0 b9 [2] 9e b5 [2] 92 bf [2] 85 b4 [2] 9e fa [2] a3 }

  condition:
    any of them
}