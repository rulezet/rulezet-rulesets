rule TTP_XOR_MULT_DOSStub_2df3 {
  strings:
    $key_2df3 = { 79 9b [2] 0d 83 [2] 4a 81 [2] 0d 90 [2] 43 9c [2] 4f 96 [2] 58 9d [2] 43 d3 [2] 7e }

  condition:
    any of them
}