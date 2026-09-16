rule TTP_XOR_MULT_DOSStub_9478 {
  strings:
    $key_9478 = { c0 10 [2] b4 08 [2] f3 0a [2] b4 1b [2] fa 17 [2] f6 1d [2] e1 16 [2] fa 58 [2] c7 }

  condition:
    any of them
}