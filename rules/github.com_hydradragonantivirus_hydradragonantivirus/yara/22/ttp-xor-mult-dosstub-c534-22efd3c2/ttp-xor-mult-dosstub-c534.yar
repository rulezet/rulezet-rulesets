rule TTP_XOR_MULT_DOSStub_c534 {
  strings:
    $key_c534 = { 91 5c [2] e5 44 [2] a2 46 [2] e5 57 [2] ab 5b [2] a7 51 [2] b0 5a [2] ab 14 [2] 96 }

  condition:
    any of them
}