rule TTP_XOR_MULT_DOSStub_c524 {
  strings:
    $key_c524 = { 91 4c [2] e5 54 [2] a2 56 [2] e5 47 [2] ab 4b [2] a7 41 [2] b0 4a [2] ab 04 [2] 96 }

  condition:
    any of them
}