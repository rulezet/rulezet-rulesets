rule TTP_XOR_MULT_DOSStub_39f3 {
  strings:
    $key_39f3 = { 6d 9b [2] 19 83 [2] 5e 81 [2] 19 90 [2] 57 9c [2] 5b 96 [2] 4c 9d [2] 57 d3 [2] 6a }

  condition:
    any of them
}