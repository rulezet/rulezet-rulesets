rule TTP_XOR_MULT_DOSStub_2c24 {
  strings:
    $key_2c24 = { 78 4c [2] 0c 54 [2] 4b 56 [2] 0c 47 [2] 42 4b [2] 4e 41 [2] 59 4a [2] 42 04 [2] 7f }

  condition:
    any of them
}