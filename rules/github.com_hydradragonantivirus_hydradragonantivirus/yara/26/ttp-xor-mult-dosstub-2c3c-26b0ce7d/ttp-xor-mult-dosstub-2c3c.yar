rule TTP_XOR_MULT_DOSStub_2c3c {
  strings:
    $key_2c3c = { 78 54 [2] 0c 4c [2] 4b 4e [2] 0c 5f [2] 42 53 [2] 4e 59 [2] 59 52 [2] 42 1c [2] 7f }

  condition:
    any of them
}