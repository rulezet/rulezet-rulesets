rule TTP_XOR_MULT_DOSStub_c46a {
  strings:
    $key_c46a = { 90 02 [2] e4 1a [2] a3 18 [2] e4 09 [2] aa 05 [2] a6 0f [2] b1 04 [2] aa 4a [2] 97 }

  condition:
    any of them
}