rule TTP_XOR_MULT_DOSStub_53f3 {
  strings:
    $key_53f3 = { 07 9b [2] 73 83 [2] 34 81 [2] 73 90 [2] 3d 9c [2] 31 96 [2] 26 9d [2] 3d d3 [2] 00 }

  condition:
    any of them
}