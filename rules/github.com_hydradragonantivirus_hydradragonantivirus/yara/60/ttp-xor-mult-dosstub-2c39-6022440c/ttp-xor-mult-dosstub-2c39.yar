rule TTP_XOR_MULT_DOSStub_2c39 {
  strings:
    $key_2c39 = { 78 51 [2] 0c 49 [2] 4b 4b [2] 0c 5a [2] 42 56 [2] 4e 5c [2] 59 57 [2] 42 19 [2] 7f }

  condition:
    any of them
}