rule TTP_XOR_MULT_DOSStub_a071 {
  strings:
    $key_a071 = { f4 19 [2] 80 01 [2] c7 03 [2] 80 12 [2] ce 1e [2] c2 14 [2] d5 1f [2] ce 51 [2] f3 }

  condition:
    any of them
}