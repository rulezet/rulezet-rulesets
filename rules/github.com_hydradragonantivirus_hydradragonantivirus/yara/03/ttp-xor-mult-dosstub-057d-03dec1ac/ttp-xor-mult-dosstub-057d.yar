rule TTP_XOR_MULT_DOSStub_057d {
  strings:
    $key_057d = { 51 15 [2] 25 0d [2] 62 0f [2] 25 1e [2] 6b 12 [2] 67 18 [2] 70 13 [2] 6b 5d [2] 56 }

  condition:
    any of them
}