rule TTP_XOR_MULT_DOSStub_840c {
  strings:
    $key_840c = { d0 64 [2] a4 7c [2] e3 7e [2] a4 6f [2] ea 63 [2] e6 69 [2] f1 62 [2] ea 2c [2] d7 }

  condition:
    any of them
}