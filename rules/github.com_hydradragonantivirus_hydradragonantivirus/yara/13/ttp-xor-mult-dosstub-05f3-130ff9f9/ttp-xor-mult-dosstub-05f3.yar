rule TTP_XOR_MULT_DOSStub_05f3 {
  strings:
    $key_05f3 = { 51 9b [2] 25 83 [2] 62 81 [2] 25 90 [2] 6b 9c [2] 67 96 [2] 70 9d [2] 6b d3 [2] 56 }

  condition:
    any of them
}