rule TTP_XOR_MULT_DOSStub_a00c {
  strings:
    $key_a00c = { f4 64 [2] 80 7c [2] c7 7e [2] 80 6f [2] ce 63 [2] c2 69 [2] d5 62 [2] ce 2c [2] f3 }

  condition:
    any of them
}