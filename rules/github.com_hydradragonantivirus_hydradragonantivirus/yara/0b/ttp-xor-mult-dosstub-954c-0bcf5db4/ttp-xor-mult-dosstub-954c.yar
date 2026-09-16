rule TTP_XOR_MULT_DOSStub_954c {
  strings:
    $key_954c = { c1 24 [2] b5 3c [2] f2 3e [2] b5 2f [2] fb 23 [2] f7 29 [2] e0 22 [2] fb 6c [2] c6 }

  condition:
    any of them
}