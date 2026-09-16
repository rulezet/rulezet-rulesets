rule TTP_XOR_MULT_DOSStub_8289 {
  strings:
    $key_8289 = { d6 e1 [2] a2 f9 [2] e5 fb [2] a2 ea [2] ec e6 [2] e0 ec [2] f7 e7 [2] ec a9 [2] d1 }

  condition:
    any of them
}