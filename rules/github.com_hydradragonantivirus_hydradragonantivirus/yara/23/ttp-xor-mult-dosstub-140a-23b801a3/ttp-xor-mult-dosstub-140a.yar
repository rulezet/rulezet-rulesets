rule TTP_XOR_MULT_DOSStub_140a {
  strings:
    $key_140a = { 40 62 [2] 34 7a [2] 73 78 [2] 34 69 [2] 7a 65 [2] 76 6f [2] 61 64 [2] 7a 2a [2] 47 }

  condition:
    any of them
}