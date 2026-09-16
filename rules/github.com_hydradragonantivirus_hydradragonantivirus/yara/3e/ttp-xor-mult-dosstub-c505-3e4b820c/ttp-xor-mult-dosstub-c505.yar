rule TTP_XOR_MULT_DOSStub_c505 {
  strings:
    $key_c505 = { 91 6d [2] e5 75 [2] a2 77 [2] e5 66 [2] ab 6a [2] a7 60 [2] b0 6b [2] ab 25 [2] 96 }

  condition:
    any of them
}