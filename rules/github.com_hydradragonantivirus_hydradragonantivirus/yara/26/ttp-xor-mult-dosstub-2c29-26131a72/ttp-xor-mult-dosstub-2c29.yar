rule TTP_XOR_MULT_DOSStub_2c29 {
  strings:
    $key_2c29 = { 78 41 [2] 0c 59 [2] 4b 5b [2] 0c 4a [2] 42 46 [2] 4e 4c [2] 59 47 [2] 42 09 [2] 7f }

  condition:
    any of them
}