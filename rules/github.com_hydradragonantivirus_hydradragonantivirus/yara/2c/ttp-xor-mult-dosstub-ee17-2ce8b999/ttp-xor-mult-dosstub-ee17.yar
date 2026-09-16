rule TTP_XOR_MULT_DOSStub_ee17 {
  strings:
    $key_ee17 = { ba 7f [2] ce 67 [2] 89 65 [2] ce 74 [2] 80 78 [2] 8c 72 [2] 9b 79 [2] 80 37 [2] bd }

  condition:
    any of them
}