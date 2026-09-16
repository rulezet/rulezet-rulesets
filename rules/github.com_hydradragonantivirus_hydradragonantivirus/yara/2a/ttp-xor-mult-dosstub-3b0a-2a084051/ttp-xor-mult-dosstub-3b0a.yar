rule TTP_XOR_MULT_DOSStub_3b0a {
  strings:
    $key_3b0a = { 6f 62 [2] 1b 7a [2] 5c 78 [2] 1b 69 [2] 55 65 [2] 59 6f [2] 4e 64 [2] 55 2a [2] 68 }

  condition:
    any of them
}