rule TTP_XOR_MULT_DOSStub_8b30 {
  strings:
    $key_8b30 = { df 58 [2] ab 40 [2] ec 42 [2] ab 53 [2] e5 5f [2] e9 55 [2] fe 5e [2] e5 10 [2] d8 }

  condition:
    any of them
}