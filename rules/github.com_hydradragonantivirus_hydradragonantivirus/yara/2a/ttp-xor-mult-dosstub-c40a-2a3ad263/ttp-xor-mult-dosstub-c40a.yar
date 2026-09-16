rule TTP_XOR_MULT_DOSStub_c40a {
  strings:
    $key_c40a = { 90 62 [2] e4 7a [2] a3 78 [2] e4 69 [2] aa 65 [2] a6 6f [2] b1 64 [2] aa 2a [2] 97 }

  condition:
    any of them
}