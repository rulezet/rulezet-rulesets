rule TTP_XOR_MULT_DOSStub_3bf3 {
  strings:
    $key_3bf3 = { 6f 9b [2] 1b 83 [2] 5c 81 [2] 1b 90 [2] 55 9c [2] 59 96 [2] 4e 9d [2] 55 d3 [2] 68 }

  condition:
    any of them
}