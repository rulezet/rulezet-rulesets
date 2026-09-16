rule TTP_XOR_MULT_DOSStub_560a {
  strings:
    $key_560a = { 02 62 [2] 76 7a [2] 31 78 [2] 76 69 [2] 38 65 [2] 34 6f [2] 23 64 [2] 38 2a [2] 05 }

  condition:
    any of them
}