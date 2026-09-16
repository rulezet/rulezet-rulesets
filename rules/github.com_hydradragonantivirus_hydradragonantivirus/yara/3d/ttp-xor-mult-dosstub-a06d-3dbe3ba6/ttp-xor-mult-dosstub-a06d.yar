rule TTP_XOR_MULT_DOSStub_a06d {
  strings:
    $key_a06d = { f4 05 [2] 80 1d [2] c7 1f [2] 80 0e [2] ce 02 [2] c2 08 [2] d5 03 [2] ce 4d [2] f3 }

  condition:
    any of them
}