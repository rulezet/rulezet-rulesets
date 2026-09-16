rule TTP_XOR_MULT_DOSStub_250a {
  strings:
    $key_250a = { 71 62 [2] 05 7a [2] 42 78 [2] 05 69 [2] 4b 65 [2] 47 6f [2] 50 64 [2] 4b 2a [2] 76 }

  condition:
    any of them
}