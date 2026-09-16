rule TTP_XOR_MULT_DOSStub_02f3 {
  strings:
    $key_02f3 = { 56 9b [2] 22 83 [2] 65 81 [2] 22 90 [2] 6c 9c [2] 60 96 [2] 77 9d [2] 6c d3 [2] 51 }

  condition:
    any of them
}