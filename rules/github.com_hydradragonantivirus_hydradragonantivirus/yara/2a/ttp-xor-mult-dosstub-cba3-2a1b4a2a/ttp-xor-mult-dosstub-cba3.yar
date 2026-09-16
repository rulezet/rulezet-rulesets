rule TTP_XOR_MULT_DOSStub_cba3 {
  strings:
    $key_cba3 = { 9f cb [2] eb d3 [2] ac d1 [2] eb c0 [2] a5 cc [2] a9 c6 [2] be cd [2] a5 83 [2] 98 }

  condition:
    any of them
}