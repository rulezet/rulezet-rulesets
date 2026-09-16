rule TTP_XOR_MULT_DOSStub_3df3 {
  strings:
    $key_3df3 = { 69 9b [2] 1d 83 [2] 5a 81 [2] 1d 90 [2] 53 9c [2] 5f 96 [2] 48 9d [2] 53 d3 [2] 6e }

  condition:
    any of them
}