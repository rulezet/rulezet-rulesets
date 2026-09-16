rule TTP_XOR_MULT_DOSStub_840f {
  strings:
    $key_840f = { d0 67 [2] a4 7f [2] e3 7d [2] a4 6c [2] ea 60 [2] e6 6a [2] f1 61 [2] ea 2f [2] d7 }

  condition:
    any of them
}