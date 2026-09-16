rule TTP_XOR_MULT_DOSStub_15f3 {
  strings:
    $key_15f3 = { 41 9b [2] 35 83 [2] 72 81 [2] 35 90 [2] 7b 9c [2] 77 96 [2] 60 9d [2] 7b d3 [2] 46 }

  condition:
    any of them
}