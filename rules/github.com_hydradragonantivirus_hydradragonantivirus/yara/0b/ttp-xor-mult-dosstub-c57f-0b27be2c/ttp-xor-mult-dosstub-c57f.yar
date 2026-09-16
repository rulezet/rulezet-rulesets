rule TTP_XOR_MULT_DOSStub_c57f {
  strings:
    $key_c57f = { 91 17 [2] e5 0f [2] a2 0d [2] e5 1c [2] ab 10 [2] a7 1a [2] b0 11 [2] ab 5f [2] 96 }

  condition:
    any of them
}