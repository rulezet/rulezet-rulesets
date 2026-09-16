rule TTP_XOR_MULT_DOSStub_a05d {
  strings:
    $key_a05d = { f4 35 [2] 80 2d [2] c7 2f [2] 80 3e [2] ce 32 [2] c2 38 [2] d5 33 [2] ce 7d [2] f3 }

  condition:
    any of them
}