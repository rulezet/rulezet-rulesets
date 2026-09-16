rule TTP_XOR_MULT_DOSStub_93f8 {
  strings:
    $key_93f8 = { c7 90 [2] b3 88 [2] f4 8a [2] b3 9b [2] fd 97 [2] f1 9d [2] e6 96 [2] fd d8 [2] c0 }

  condition:
    any of them
}