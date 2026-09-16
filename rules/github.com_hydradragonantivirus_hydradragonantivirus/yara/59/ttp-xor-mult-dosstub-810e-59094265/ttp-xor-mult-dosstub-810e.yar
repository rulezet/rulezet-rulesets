rule TTP_XOR_MULT_DOSStub_810e {
  strings:
    $key_810e = { d5 66 [2] a1 7e [2] e6 7c [2] a1 6d [2] ef 61 [2] e3 6b [2] f4 60 [2] ef 2e [2] d2 }

  condition:
    any of them
}