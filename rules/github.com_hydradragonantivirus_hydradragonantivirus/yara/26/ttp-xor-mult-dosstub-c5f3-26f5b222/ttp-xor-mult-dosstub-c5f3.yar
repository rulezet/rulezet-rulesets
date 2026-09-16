rule TTP_XOR_MULT_DOSStub_c5f3 {
  strings:
    $key_c5f3 = { 91 9b [2] e5 83 [2] a2 81 [2] e5 90 [2] ab 9c [2] a7 96 [2] b0 9d [2] ab d3 [2] 96 }

  condition:
    any of them
}