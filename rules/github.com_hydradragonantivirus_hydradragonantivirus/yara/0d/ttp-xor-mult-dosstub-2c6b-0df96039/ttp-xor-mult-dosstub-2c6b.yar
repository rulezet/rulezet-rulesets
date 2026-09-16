rule TTP_XOR_MULT_DOSStub_2c6b {
  strings:
    $key_2c6b = { 78 03 [2] 0c 1b [2] 4b 19 [2] 0c 08 [2] 42 04 [2] 4e 0e [2] 59 05 [2] 42 4b [2] 7f }

  condition:
    any of them
}