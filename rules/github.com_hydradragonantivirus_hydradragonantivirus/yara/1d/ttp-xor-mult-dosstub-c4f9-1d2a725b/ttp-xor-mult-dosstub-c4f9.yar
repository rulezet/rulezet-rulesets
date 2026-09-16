rule TTP_XOR_MULT_DOSStub_c4f9 {
  strings:
    $key_c4f9 = { 90 91 [2] e4 89 [2] a3 8b [2] e4 9a [2] aa 96 [2] a6 9c [2] b1 97 [2] aa d9 [2] 97 }

  condition:
    any of them
}