rule TTP_XOR_MULT_DOSStub_93f6 {
  strings:
    $key_93f6 = { c7 9e [2] b3 86 [2] f4 84 [2] b3 95 [2] fd 99 [2] f1 93 [2] e6 98 [2] fd d6 [2] c0 }

  condition:
    any of them
}