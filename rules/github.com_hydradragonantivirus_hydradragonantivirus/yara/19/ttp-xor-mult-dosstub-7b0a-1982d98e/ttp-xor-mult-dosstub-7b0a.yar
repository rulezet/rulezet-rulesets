rule TTP_XOR_MULT_DOSStub_7b0a {
  strings:
    $key_7b0a = { 2f 62 [2] 5b 7a [2] 1c 78 [2] 5b 69 [2] 15 65 [2] 19 6f [2] 0e 64 [2] 15 2a [2] 28 }

  condition:
    any of them
}