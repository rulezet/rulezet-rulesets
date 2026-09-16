rule TTP_XOR_MULT_DOSStub_ac07 {
  strings:
    $key_ac07 = { f8 6f [2] 8c 77 [2] cb 75 [2] 8c 64 [2] c2 68 [2] ce 62 [2] d9 69 [2] c2 27 [2] ff }

  condition:
    any of them
}