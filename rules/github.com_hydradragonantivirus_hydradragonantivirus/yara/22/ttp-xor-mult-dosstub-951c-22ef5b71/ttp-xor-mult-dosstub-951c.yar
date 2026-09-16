rule TTP_XOR_MULT_DOSStub_951c {
  strings:
    $key_951c = { c1 74 [2] b5 6c [2] f2 6e [2] b5 7f [2] fb 73 [2] f7 79 [2] e0 72 [2] fb 3c [2] c6 }

  condition:
    any of them
}