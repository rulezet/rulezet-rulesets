rule TTP_XOR_MULT_DOSStub_ee30 {
  strings:
    $key_ee30 = { ba 58 [2] ce 40 [2] 89 42 [2] ce 53 [2] 80 5f [2] 8c 55 [2] 9b 5e [2] 80 10 [2] bd }

  condition:
    any of them
}