rule TTP_XOR_MULT_DOSStub_6c38 {
  strings:
    $key_6c38 = { 38 50 [2] 4c 48 [2] 0b 4a [2] 4c 5b [2] 02 57 [2] 0e 5d [2] 19 56 [2] 02 18 [2] 3f }

  condition:
    any of them
}