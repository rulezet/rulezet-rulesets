rule TTP_XOR_MULT_DOSStub_c162 {
  strings:
    $key_c162 = { 95 0a [2] e1 12 [2] a6 10 [2] e1 01 [2] af 0d [2] a3 07 [2] b4 0c [2] af 42 [2] 92 }

  condition:
    any of them
}