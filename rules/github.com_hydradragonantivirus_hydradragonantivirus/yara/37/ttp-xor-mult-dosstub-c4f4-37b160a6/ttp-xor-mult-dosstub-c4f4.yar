rule TTP_XOR_MULT_DOSStub_c4f4 {
  strings:
    $key_c4f4 = { 90 9c [2] e4 84 [2] a3 86 [2] e4 97 [2] aa 9b [2] a6 91 [2] b1 9a [2] aa d4 [2] 97 }

  condition:
    any of them
}