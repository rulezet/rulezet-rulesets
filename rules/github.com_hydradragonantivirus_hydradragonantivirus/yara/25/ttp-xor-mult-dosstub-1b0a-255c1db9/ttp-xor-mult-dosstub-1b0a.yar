rule TTP_XOR_MULT_DOSStub_1b0a {
  strings:
    $key_1b0a = { 4f 62 [2] 3b 7a [2] 7c 78 [2] 3b 69 [2] 75 65 [2] 79 6f [2] 6e 64 [2] 75 2a [2] 48 }

  condition:
    any of them
}