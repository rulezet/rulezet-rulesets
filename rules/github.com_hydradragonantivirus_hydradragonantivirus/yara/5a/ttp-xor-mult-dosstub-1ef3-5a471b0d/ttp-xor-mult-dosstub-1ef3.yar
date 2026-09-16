rule TTP_XOR_MULT_DOSStub_1ef3 {
  strings:
    $key_1ef3 = { 4a 9b [2] 3e 83 [2] 79 81 [2] 3e 90 [2] 70 9c [2] 7c 96 [2] 6b 9d [2] 70 d3 [2] 4d }

  condition:
    any of them
}