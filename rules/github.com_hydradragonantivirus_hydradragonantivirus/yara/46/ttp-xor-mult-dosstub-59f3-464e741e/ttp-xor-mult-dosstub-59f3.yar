rule TTP_XOR_MULT_DOSStub_59f3 {
  strings:
    $key_59f3 = { 0d 9b [2] 79 83 [2] 3e 81 [2] 79 90 [2] 37 9c [2] 3b 96 [2] 2c 9d [2] 37 d3 [2] 0a }

  condition:
    any of them
}