rule TTP_XOR_MULT_DOSStub_c53f {
  strings:
    $key_c53f = { 91 57 [2] e5 4f [2] a2 4d [2] e5 5c [2] ab 50 [2] a7 5a [2] b0 51 [2] ab 1f [2] 96 }

  condition:
    any of them
}