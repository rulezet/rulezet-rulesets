rule TTP_XOR_MULT_DOSStub_9421 {
  strings:
    $key_9421 = { c0 49 [2] b4 51 [2] f3 53 [2] b4 42 [2] fa 4e [2] f6 44 [2] e1 4f [2] fa 01 [2] c7 }

  condition:
    any of them
}