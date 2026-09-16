rule TTP_XOR_MULT_DOSStub_eef3 {
  strings:
    $key_eef3 = { ba 9b [2] ce 83 [2] 89 81 [2] ce 90 [2] 80 9c [2] 8c 96 [2] 9b 9d [2] 80 d3 [2] bd }

  condition:
    any of them
}