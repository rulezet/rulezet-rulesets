rule TTP_XOR_MULT_DOSStub_01f3 {
  strings:
    $key_01f3 = { 55 9b [2] 21 83 [2] 66 81 [2] 21 90 [2] 6f 9c [2] 63 96 [2] 74 9d [2] 6f d3 [2] 52 }

  condition:
    any of them
}