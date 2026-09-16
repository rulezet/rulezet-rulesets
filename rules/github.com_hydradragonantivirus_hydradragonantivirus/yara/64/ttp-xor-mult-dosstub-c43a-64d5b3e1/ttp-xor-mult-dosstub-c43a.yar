rule TTP_XOR_MULT_DOSStub_c43a {
  strings:
    $key_c43a = { 90 52 [2] e4 4a [2] a3 48 [2] e4 59 [2] aa 55 [2] a6 5f [2] b1 54 [2] aa 1a [2] 97 }

  condition:
    any of them
}