rule TTP_XOR_MULT_DOSStub_26f3 {
  strings:
    $key_26f3 = { 72 9b [2] 06 83 [2] 41 81 [2] 06 90 [2] 48 9c [2] 44 96 [2] 53 9d [2] 48 d3 [2] 75 }

  condition:
    any of them
}