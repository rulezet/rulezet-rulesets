rule TTP_XOR_MULT_DOSStub_943c {
  strings:
    $key_943c = { c0 54 [2] b4 4c [2] f3 4e [2] b4 5f [2] fa 53 [2] f6 59 [2] e1 52 [2] fa 1c [2] c7 }

  condition:
    any of them
}