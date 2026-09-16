rule TTP_XOR_MULT_DOSStub_9aa8 {
  strings:
    $key_9aa8 = { ce c0 [2] ba d8 [2] fd da [2] ba cb [2] f4 c7 [2] f8 cd [2] ef c6 [2] f4 88 [2] c9 }

  condition:
    any of them
}