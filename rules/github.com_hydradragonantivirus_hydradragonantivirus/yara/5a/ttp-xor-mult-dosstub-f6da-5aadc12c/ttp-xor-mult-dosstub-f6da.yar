rule TTP_XOR_MULT_DOSStub_f6da {
  strings:
    $key_f6da = { a2 b2 [2] d6 aa [2] 91 a8 [2] d6 b9 [2] 98 b5 [2] 94 bf [2] 83 b4 [2] 98 fa [2] a5 }

  condition:
    any of them
}