rule TTP_XOR_MULT_DOSStub_9560 {
  strings:
    $key_9560 = { c1 08 [2] b5 10 [2] f2 12 [2] b5 03 [2] fb 0f [2] f7 05 [2] e0 0e [2] fb 40 [2] c6 }

  condition:
    any of them
}