rule TTP_XOR_MULT_DOSStub_156a {
  strings:
    $key_156a = { 41 02 [2] 35 1a [2] 72 18 [2] 35 09 [2] 7b 05 [2] 77 0f [2] 60 04 [2] 7b 4a [2] 46 }

  condition:
    any of them
}