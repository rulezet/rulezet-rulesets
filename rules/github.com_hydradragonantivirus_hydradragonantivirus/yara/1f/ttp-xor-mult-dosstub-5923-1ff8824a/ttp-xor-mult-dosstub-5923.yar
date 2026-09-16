rule TTP_XOR_MULT_DOSStub_5923 {
  strings:
    $key_5923 = { 0d 4b [2] 79 53 [2] 3e 51 [2] 79 40 [2] 37 4c [2] 3b 46 [2] 2c 4d [2] 37 03 [2] 0a }

  condition:
    any of them
}