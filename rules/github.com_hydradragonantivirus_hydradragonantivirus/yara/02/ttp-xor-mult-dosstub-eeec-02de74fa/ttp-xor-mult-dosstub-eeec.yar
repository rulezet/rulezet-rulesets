rule TTP_XOR_MULT_DOSStub_eeec {
  strings:
    $key_eeec = { ba 84 [2] ce 9c [2] 89 9e [2] ce 8f [2] 80 83 [2] 8c 89 [2] 9b 82 [2] 80 cc [2] bd }

  condition:
    any of them
}