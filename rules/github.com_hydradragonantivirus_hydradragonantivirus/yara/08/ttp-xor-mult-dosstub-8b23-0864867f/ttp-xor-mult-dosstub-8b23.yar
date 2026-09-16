rule TTP_XOR_MULT_DOSStub_8b23 {
  strings:
    $key_8b23 = { df 4b [2] ab 53 [2] ec 51 [2] ab 40 [2] e5 4c [2] e9 46 [2] fe 4d [2] e5 03 [2] d8 }

  condition:
    any of them
}