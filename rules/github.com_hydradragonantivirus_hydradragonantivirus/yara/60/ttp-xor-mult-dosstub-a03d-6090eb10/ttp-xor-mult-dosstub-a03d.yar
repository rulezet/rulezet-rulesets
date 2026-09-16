rule TTP_XOR_MULT_DOSStub_a03d {
  strings:
    $key_a03d = { f4 55 [2] 80 4d [2] c7 4f [2] 80 5e [2] ce 52 [2] c2 58 [2] d5 53 [2] ce 1d [2] f3 }

  condition:
    any of them
}