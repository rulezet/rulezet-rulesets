rule TTP_XOR_MULT_DOSStub_c53c {
  strings:
    $key_c53c = { 91 54 [2] e5 4c [2] a2 4e [2] e5 5f [2] ab 53 [2] a7 59 [2] b0 52 [2] ab 1c [2] 96 }

  condition:
    any of them
}