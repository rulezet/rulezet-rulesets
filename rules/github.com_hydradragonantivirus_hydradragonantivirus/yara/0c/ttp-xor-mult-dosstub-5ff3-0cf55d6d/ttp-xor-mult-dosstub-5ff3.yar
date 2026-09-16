rule TTP_XOR_MULT_DOSStub_5ff3 {
  strings:
    $key_5ff3 = { 0b 9b [2] 7f 83 [2] 38 81 [2] 7f 90 [2] 31 9c [2] 3d 96 [2] 2a 9d [2] 31 d3 [2] 0c }

  condition:
    any of them
}