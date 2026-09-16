rule TTP_XOR_MULT_DOSStub_93f1 {
  strings:
    $key_93f1 = { c7 99 [2] b3 81 [2] f4 83 [2] b3 92 [2] fd 9e [2] f1 94 [2] e6 9f [2] fd d1 [2] c0 }

  condition:
    any of them
}