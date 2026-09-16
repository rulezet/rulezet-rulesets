rule TTP_XOR_MULT_DOSStub_8b73 {
  strings:
    $key_8b73 = { df 1b [2] ab 03 [2] ec 01 [2] ab 10 [2] e5 1c [2] e9 16 [2] fe 1d [2] e5 53 [2] d8 }

  condition:
    any of them
}