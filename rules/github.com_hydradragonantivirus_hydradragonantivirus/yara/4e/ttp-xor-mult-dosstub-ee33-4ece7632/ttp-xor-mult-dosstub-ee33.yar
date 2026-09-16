rule TTP_XOR_MULT_DOSStub_ee33 {
  strings:
    $key_ee33 = { ba 5b [2] ce 43 [2] 89 41 [2] ce 50 [2] 80 5c [2] 8c 56 [2] 9b 5d [2] 80 13 [2] bd }

  condition:
    any of them
}