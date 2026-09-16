rule TTP_XOR_MULT_DOSStub_7ef3 {
  strings:
    $key_7ef3 = { 2a 9b [2] 5e 83 [2] 19 81 [2] 5e 90 [2] 10 9c [2] 1c 96 [2] 0b 9d [2] 10 d3 [2] 2d }

  condition:
    any of them
}