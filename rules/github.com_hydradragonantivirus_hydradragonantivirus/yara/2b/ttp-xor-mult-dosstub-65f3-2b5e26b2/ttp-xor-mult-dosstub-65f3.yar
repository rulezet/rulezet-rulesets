rule TTP_XOR_MULT_DOSStub_65f3 {
  strings:
    $key_65f3 = { 31 9b [2] 45 83 [2] 02 81 [2] 45 90 [2] 0b 9c [2] 07 96 [2] 10 9d [2] 0b d3 [2] 36 }

  condition:
    any of them
}