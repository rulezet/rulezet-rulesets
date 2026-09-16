rule TTP_XOR_MULT_DOSStub_0af3 {
  strings:
    $key_0af3 = { 5e 9b [2] 2a 83 [2] 6d 81 [2] 2a 90 [2] 64 9c [2] 68 96 [2] 7f 9d [2] 64 d3 [2] 59 }

  condition:
    any of them
}