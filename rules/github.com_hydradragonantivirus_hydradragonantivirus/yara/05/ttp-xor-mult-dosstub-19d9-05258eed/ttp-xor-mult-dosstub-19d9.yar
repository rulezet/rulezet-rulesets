rule TTP_XOR_MULT_DOSStub_19d9 {
  strings:
    $key_19d9 = { 4d b1 [2] 39 a9 [2] 7e ab [2] 39 ba [2] 77 b6 [2] 7b bc [2] 6c b7 [2] 77 f9 [2] 4a }

  condition:
    any of them
}