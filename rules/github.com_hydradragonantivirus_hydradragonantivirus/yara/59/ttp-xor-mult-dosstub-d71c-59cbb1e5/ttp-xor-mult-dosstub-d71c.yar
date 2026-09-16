rule TTP_XOR_MULT_DOSStub_d71c {
  strings:
    $key_d71c = { 83 74 [2] f7 6c [2] b0 6e [2] f7 7f [2] b9 73 [2] b5 79 [2] a2 72 [2] b9 3c [2] 84 }

  condition:
    any of them
}