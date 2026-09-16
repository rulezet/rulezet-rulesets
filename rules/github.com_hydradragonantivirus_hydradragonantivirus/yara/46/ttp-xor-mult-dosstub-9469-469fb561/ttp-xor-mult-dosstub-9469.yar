rule TTP_XOR_MULT_DOSStub_9469 {
  strings:
    $key_9469 = { c0 01 [2] b4 19 [2] f3 1b [2] b4 0a [2] fa 06 [2] f6 0c [2] e1 07 [2] fa 49 [2] c7 }

  condition:
    any of them
}