rule TTP_XOR_MULT_DOSStub_825c {
  strings:
    $key_825c = { d6 34 [2] a2 2c [2] e5 2e [2] a2 3f [2] ec 33 [2] e0 39 [2] f7 32 [2] ec 7c [2] d1 }

  condition:
    any of them
}