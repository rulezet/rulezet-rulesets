rule TTP_XOR_MULT_DOSStub_c13a {
  strings:
    $key_c13a = { 95 52 [2] e1 4a [2] a6 48 [2] e1 59 [2] af 55 [2] a3 5f [2] b4 54 [2] af 1a [2] 92 }

  condition:
    any of them
}