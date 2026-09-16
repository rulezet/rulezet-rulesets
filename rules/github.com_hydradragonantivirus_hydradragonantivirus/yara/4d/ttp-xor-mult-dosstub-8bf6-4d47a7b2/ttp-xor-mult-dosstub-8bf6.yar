rule TTP_XOR_MULT_DOSStub_8bf6 {
  strings:
    $key_8bf6 = { df 9e [2] ab 86 [2] ec 84 [2] ab 95 [2] e5 99 [2] e9 93 [2] fe 98 [2] e5 d6 [2] d8 }

  condition:
    any of them
}