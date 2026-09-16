rule TTP_XOR_MULT_DOSStub_35f3 {
  strings:
    $key_35f3 = { 61 9b [2] 15 83 [2] 52 81 [2] 15 90 [2] 5b 9c [2] 57 96 [2] 40 9d [2] 5b d3 [2] 66 }

  condition:
    any of them
}