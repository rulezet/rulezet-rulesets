rule TTP_XOR_MULT_DOSStub_c57a {
  strings:
    $key_c57a = { 91 12 [2] e5 0a [2] a2 08 [2] e5 19 [2] ab 15 [2] a7 1f [2] b0 14 [2] ab 5a [2] 96 }

  condition:
    any of them
}