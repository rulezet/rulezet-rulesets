rule TTP_XOR_MULT_DOSStub_c10a {
  strings:
    $key_c10a = { 95 62 [2] e1 7a [2] a6 78 [2] e1 69 [2] af 65 [2] a3 6f [2] b4 64 [2] af 2a [2] 92 }

  condition:
    any of them
}