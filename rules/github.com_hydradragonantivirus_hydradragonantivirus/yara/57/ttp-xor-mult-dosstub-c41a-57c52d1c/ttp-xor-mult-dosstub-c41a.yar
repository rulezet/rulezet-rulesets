rule TTP_XOR_MULT_DOSStub_c41a {
  strings:
    $key_c41a = { 90 72 [2] e4 6a [2] a3 68 [2] e4 79 [2] aa 75 [2] a6 7f [2] b1 74 [2] aa 3a [2] 97 }

  condition:
    any of them
}