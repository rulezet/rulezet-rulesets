rule TTP_XOR_MULT_DOSStub_2c18 {
  strings:
    $key_2c18 = { 78 70 [2] 0c 68 [2] 4b 6a [2] 0c 7b [2] 42 77 [2] 4e 7d [2] 59 76 [2] 42 38 [2] 7f }

  condition:
    any of them
}