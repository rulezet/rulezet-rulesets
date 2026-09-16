rule TTP_XOR_MULT_DOSStub_93fa {
  strings:
    $key_93fa = { c7 92 [2] b3 8a [2] f4 88 [2] b3 99 [2] fd 95 [2] f1 9f [2] e6 94 [2] fd da [2] c0 }

  condition:
    any of them
}