rule TTP_XOR_MULT_DOSStub_2c23 {
  strings:
    $key_2c23 = { 78 4b [2] 0c 53 [2] 4b 51 [2] 0c 40 [2] 42 4c [2] 4e 46 [2] 59 4d [2] 42 03 [2] 7f }

  condition:
    any of them
}