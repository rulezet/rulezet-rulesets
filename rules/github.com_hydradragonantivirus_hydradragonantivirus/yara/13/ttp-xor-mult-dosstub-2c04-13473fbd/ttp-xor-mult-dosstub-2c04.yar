rule TTP_XOR_MULT_DOSStub_2c04 {
  strings:
    $key_2c04 = { 78 6c [2] 0c 74 [2] 4b 76 [2] 0c 67 [2] 42 6b [2] 4e 61 [2] 59 6a [2] 42 24 [2] 7f }

  condition:
    any of them
}