rule TTP_XOR_MULT_DOSStub_e8f3 {
  strings:
    $key_e8f3 = { bc 9b [2] c8 83 [2] 8f 81 [2] c8 90 [2] 86 9c [2] 8a 96 [2] 9d 9d [2] 86 d3 [2] bb }

  condition:
    any of them
}