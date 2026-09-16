rule TTP_XOR_MULT_DOSStub_3c18 {
  strings:
    $key_3c18 = { 68 70 [2] 1c 68 [2] 5b 6a [2] 1c 7b [2] 52 77 [2] 5e 7d [2] 49 76 [2] 52 38 [2] 6f }

  condition:
    any of them
}