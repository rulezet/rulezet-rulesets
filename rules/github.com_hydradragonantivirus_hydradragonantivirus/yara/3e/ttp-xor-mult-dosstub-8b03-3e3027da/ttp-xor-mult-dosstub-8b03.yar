rule TTP_XOR_MULT_DOSStub_8b03 {
  strings:
    $key_8b03 = { df 6b [2] ab 73 [2] ec 71 [2] ab 60 [2] e5 6c [2] e9 66 [2] fe 6d [2] e5 23 [2] d8 }

  condition:
    any of them
}