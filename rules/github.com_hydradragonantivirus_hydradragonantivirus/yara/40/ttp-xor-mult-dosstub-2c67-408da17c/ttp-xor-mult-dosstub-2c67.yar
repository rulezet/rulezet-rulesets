rule TTP_XOR_MULT_DOSStub_2c67 {
  strings:
    $key_2c67 = { 78 0f [2] 0c 17 [2] 4b 15 [2] 0c 04 [2] 42 08 [2] 4e 02 [2] 59 09 [2] 42 47 [2] 7f }

  condition:
    any of them
}