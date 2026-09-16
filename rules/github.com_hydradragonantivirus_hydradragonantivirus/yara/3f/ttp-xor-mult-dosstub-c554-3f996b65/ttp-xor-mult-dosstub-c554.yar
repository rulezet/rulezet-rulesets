rule TTP_XOR_MULT_DOSStub_c554 {
  strings:
    $key_c554 = { 91 3c [2] e5 24 [2] a2 26 [2] e5 37 [2] ab 3b [2] a7 31 [2] b0 3a [2] ab 74 [2] 96 }

  condition:
    any of them
}