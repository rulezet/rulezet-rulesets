rule TTP_XOR_MULT_DOSStub_45f3 {
  strings:
    $key_45f3 = { 11 9b [2] 65 83 [2] 22 81 [2] 65 90 [2] 2b 9c [2] 27 96 [2] 30 9d [2] 2b d3 [2] 16 }

  condition:
    any of them
}