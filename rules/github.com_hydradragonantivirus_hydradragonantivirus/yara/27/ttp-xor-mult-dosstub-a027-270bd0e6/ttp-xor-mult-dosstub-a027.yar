rule TTP_XOR_MULT_DOSStub_a027 {
  strings:
    $key_a027 = { f4 4f [2] 80 57 [2] c7 55 [2] 80 44 [2] ce 48 [2] c2 42 [2] d5 49 [2] ce 07 [2] f3 }

  condition:
    any of them
}