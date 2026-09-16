rule TTP_XOR_MULT_DOSStub_8b3c {
  strings:
    $key_8b3c = { df 54 [2] ab 4c [2] ec 4e [2] ab 5f [2] e5 53 [2] e9 59 [2] fe 52 [2] e5 1c [2] d8 }

  condition:
    any of them
}