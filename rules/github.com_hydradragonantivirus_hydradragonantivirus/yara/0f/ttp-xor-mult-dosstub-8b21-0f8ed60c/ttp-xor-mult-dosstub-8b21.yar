rule TTP_XOR_MULT_DOSStub_8b21 {
  strings:
    $key_8b21 = { df 49 [2] ab 51 [2] ec 53 [2] ab 42 [2] e5 4e [2] e9 44 [2] fe 4f [2] e5 01 [2] d8 }

  condition:
    any of them
}