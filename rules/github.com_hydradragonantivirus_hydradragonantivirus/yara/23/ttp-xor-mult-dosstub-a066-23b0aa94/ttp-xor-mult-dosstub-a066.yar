rule TTP_XOR_MULT_DOSStub_a066 {
  strings:
    $key_a066 = { f4 0e [2] 80 16 [2] c7 14 [2] 80 05 [2] ce 09 [2] c2 03 [2] d5 08 [2] ce 46 [2] f3 }

  condition:
    any of them
}