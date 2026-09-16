rule TTP_XOR_MULT_DOSStub_830f {
  strings:
    $key_830f = { d7 67 [2] a3 7f [2] e4 7d [2] a3 6c [2] ed 60 [2] e1 6a [2] f6 61 [2] ed 2f [2] d0 }

  condition:
    any of them
}