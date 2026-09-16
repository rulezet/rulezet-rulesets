rule TTP_XOR_MULT_DOSStub_d5fc {
  strings:
    $key_d5fc = { 81 94 [2] f5 8c [2] b2 8e [2] f5 9f [2] bb 93 [2] b7 99 [2] a0 92 [2] bb dc [2] 86 }

  condition:
    any of them
}