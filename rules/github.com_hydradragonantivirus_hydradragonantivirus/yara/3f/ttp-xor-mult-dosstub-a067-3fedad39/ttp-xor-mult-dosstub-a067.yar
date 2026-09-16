rule TTP_XOR_MULT_DOSStub_a067 {
  strings:
    $key_a067 = { f4 0f [2] 80 17 [2] c7 15 [2] 80 04 [2] ce 08 [2] c2 02 [2] d5 09 [2] ce 47 [2] f3 }

  condition:
    any of them
}