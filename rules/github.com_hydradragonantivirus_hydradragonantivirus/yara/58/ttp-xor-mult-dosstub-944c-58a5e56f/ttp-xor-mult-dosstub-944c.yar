rule TTP_XOR_MULT_DOSStub_944c {
  strings:
    $key_944c = { c0 24 [2] b4 3c [2] f3 3e [2] b4 2f [2] fa 23 [2] f6 29 [2] e1 22 [2] fa 6c [2] c7 }

  condition:
    any of them
}