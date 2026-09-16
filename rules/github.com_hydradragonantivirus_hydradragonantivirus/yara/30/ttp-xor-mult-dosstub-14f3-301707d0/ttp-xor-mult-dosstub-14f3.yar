rule TTP_XOR_MULT_DOSStub_14f3 {
  strings:
    $key_14f3 = { 40 9b [2] 34 83 [2] 73 81 [2] 34 90 [2] 7a 9c [2] 76 96 [2] 61 9d [2] 7a d3 [2] 47 }

  condition:
    any of them
}