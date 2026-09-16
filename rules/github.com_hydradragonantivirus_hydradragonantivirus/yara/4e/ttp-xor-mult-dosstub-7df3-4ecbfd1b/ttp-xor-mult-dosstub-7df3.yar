rule TTP_XOR_MULT_DOSStub_7df3 {
  strings:
    $key_7df3 = { 29 9b [2] 5d 83 [2] 1a 81 [2] 5d 90 [2] 13 9c [2] 1f 96 [2] 08 9d [2] 13 d3 [2] 2e }

  condition:
    any of them
}