rule TTP_XOR_MULT_DOSStub_c533 {
  strings:
    $key_c533 = { 91 5b [2] e5 43 [2] a2 41 [2] e5 50 [2] ab 5c [2] a7 56 [2] b0 5d [2] ab 13 [2] 96 }

  condition:
    any of them
}