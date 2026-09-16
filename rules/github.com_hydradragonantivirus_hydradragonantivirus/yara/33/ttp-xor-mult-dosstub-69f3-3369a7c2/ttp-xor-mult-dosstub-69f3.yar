rule TTP_XOR_MULT_DOSStub_69f3 {
  strings:
    $key_69f3 = { 3d 9b [2] 49 83 [2] 0e 81 [2] 49 90 [2] 07 9c [2] 0b 96 [2] 1c 9d [2] 07 d3 [2] 3a }

  condition:
    any of them
}