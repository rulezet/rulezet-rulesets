rule TTP_XOR_MULT_DOSStub_c55f {
  strings:
    $key_c55f = { 91 37 [2] e5 2f [2] a2 2d [2] e5 3c [2] ab 30 [2] a7 3a [2] b0 31 [2] ab 7f [2] 96 }

  condition:
    any of them
}