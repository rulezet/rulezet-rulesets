rule TTP_XOR_MULT_DOSStub_9521 {
  strings:
    $key_9521 = { c1 49 [2] b5 51 [2] f2 53 [2] b5 42 [2] fb 4e [2] f7 44 [2] e0 4f [2] fb 01 [2] c6 }

  condition:
    any of them
}