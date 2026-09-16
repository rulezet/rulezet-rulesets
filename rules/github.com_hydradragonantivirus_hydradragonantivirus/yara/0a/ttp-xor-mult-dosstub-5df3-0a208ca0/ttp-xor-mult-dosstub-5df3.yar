rule TTP_XOR_MULT_DOSStub_5df3 {
  strings:
    $key_5df3 = { 09 9b [2] 7d 83 [2] 3a 81 [2] 7d 90 [2] 33 9c [2] 3f 96 [2] 28 9d [2] 33 d3 [2] 0e }

  condition:
    any of them
}