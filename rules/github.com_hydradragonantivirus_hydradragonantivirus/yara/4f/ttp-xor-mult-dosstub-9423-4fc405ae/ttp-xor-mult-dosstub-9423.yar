rule TTP_XOR_MULT_DOSStub_9423 {
  strings:
    $key_9423 = { c0 4b [2] b4 53 [2] f3 51 [2] b4 40 [2] fa 4c [2] f6 46 [2] e1 4d [2] fa 03 [2] c7 }

  condition:
    any of them
}