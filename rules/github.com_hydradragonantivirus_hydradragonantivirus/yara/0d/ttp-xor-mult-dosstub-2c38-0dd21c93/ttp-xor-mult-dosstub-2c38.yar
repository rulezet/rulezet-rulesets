rule TTP_XOR_MULT_DOSStub_2c38 {
  strings:
    $key_2c38 = { 78 50 [2] 0c 48 [2] 4b 4a [2] 0c 5b [2] 42 57 [2] 4e 5d [2] 59 56 [2] 42 18 [2] 7f }

  condition:
    any of them
}