rule TTP_XOR_MULT_DOSStub_9aa2 {
  strings:
    $key_9aa2 = { ce ca [2] ba d2 [2] fd d0 [2] ba c1 [2] f4 cd [2] f8 c7 [2] ef cc [2] f4 82 [2] c9 }

  condition:
    any of them
}