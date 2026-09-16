rule TTP_XOR_MULT_DOSStub_c47a {
  strings:
    $key_c47a = { 90 12 [2] e4 0a [2] a3 08 [2] e4 19 [2] aa 15 [2] a6 1f [2] b1 14 [2] aa 5a [2] 97 }

  condition:
    any of them
}