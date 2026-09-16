rule TTP_XOR_MULT_DOSStub_9466 {
  strings:
    $key_9466 = { c0 0e [2] b4 16 [2] f3 14 [2] b4 05 [2] fa 09 [2] f6 03 [2] e1 08 [2] fa 46 [2] c7 }

  condition:
    any of them
}