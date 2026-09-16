rule TTP_XOR_MULT_DOSStub_c529 {
  strings:
    $key_c529 = { 91 41 [2] e5 59 [2] a2 5b [2] e5 4a [2] ab 46 [2] a7 4c [2] b0 47 [2] ab 09 [2] 96 }

  condition:
    any of them
}