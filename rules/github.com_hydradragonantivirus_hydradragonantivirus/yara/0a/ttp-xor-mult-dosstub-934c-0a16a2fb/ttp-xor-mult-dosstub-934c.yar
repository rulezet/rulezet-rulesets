rule TTP_XOR_MULT_DOSStub_934c {
  strings:
    $key_934c = { c7 24 [2] b3 3c [2] f4 3e [2] b3 2f [2] fd 23 [2] f1 29 [2] e6 22 [2] fd 6c [2] c0 }

  condition:
    any of them
}