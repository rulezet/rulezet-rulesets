rule TTP_XOR_MULT_DOSStub_9426 {
  strings:
    $key_9426 = { c0 4e [2] b4 56 [2] f3 54 [2] b4 45 [2] fa 49 [2] f6 43 [2] e1 48 [2] fa 06 [2] c7 }

  condition:
    any of them
}