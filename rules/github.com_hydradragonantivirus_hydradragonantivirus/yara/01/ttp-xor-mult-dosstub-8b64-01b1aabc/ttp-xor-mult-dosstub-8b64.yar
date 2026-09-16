rule TTP_XOR_MULT_DOSStub_8b64 {
  strings:
    $key_8b64 = { df 0c [2] ab 14 [2] ec 16 [2] ab 07 [2] e5 0b [2] e9 01 [2] fe 0a [2] e5 44 [2] d8 }

  condition:
    any of them
}