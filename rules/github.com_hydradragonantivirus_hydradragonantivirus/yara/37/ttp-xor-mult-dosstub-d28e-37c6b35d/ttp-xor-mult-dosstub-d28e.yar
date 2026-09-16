rule TTP_XOR_MULT_DOSStub_d28e {
  strings:
    $key_d28e = { 86 e6 [2] f2 fe [2] b5 fc [2] f2 ed [2] bc e1 [2] b0 eb [2] a7 e0 [2] bc ae [2] 81 }

  condition:
    any of them
}