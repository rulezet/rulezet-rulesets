rule TTP_XOR_MULT_DOSStub_09f3 {
  strings:
    $key_09f3 = { 5d 9b [2] 29 83 [2] 6e 81 [2] 29 90 [2] 67 9c [2] 6b 96 [2] 7c 9d [2] 67 d3 [2] 5a }

  condition:
    any of them
}