rule TTP_XOR_MULT_DOSStub_34f3 {
  strings:
    $key_34f3 = { 60 9b [2] 14 83 [2] 53 81 [2] 14 90 [2] 5a 9c [2] 56 96 [2] 41 9d [2] 5a d3 [2] 67 }

  condition:
    any of them
}