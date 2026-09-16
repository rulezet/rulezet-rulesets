rule TTP_XOR_MULT_DOSStub_9667 {
  strings:
    $key_9667 = { c2 0f [2] b6 17 [2] f1 15 [2] b6 04 [2] f8 08 [2] f4 02 [2] e3 09 [2] f8 47 [2] c5 }

  condition:
    any of them
}