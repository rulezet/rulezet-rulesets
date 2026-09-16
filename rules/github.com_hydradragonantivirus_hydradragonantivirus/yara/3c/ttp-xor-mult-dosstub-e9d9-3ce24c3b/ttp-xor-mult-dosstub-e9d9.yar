rule TTP_XOR_MULT_DOSStub_e9d9 {
  strings:
    $key_e9d9 = { bd b1 [2] c9 a9 [2] 8e ab [2] c9 ba [2] 87 b6 [2] 8b bc [2] 9c b7 [2] 87 f9 [2] ba }

  condition:
    any of them
}