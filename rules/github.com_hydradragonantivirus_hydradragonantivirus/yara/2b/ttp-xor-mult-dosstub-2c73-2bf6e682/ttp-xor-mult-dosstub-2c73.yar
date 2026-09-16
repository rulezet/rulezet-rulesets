rule TTP_XOR_MULT_DOSStub_2c73 {
  strings:
    $key_2c73 = { 78 1b [2] 0c 03 [2] 4b 01 [2] 0c 10 [2] 42 1c [2] 4e 16 [2] 59 1d [2] 42 53 [2] 7f }

  condition:
    any of them
}