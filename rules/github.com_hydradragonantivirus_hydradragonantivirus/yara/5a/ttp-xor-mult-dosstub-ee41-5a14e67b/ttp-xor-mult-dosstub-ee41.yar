rule TTP_XOR_MULT_DOSStub_ee41 {
  strings:
    $key_ee41 = { ba 29 [2] ce 31 [2] 89 33 [2] ce 22 [2] 80 2e [2] 8c 24 [2] 9b 2f [2] 80 61 [2] bd }

  condition:
    any of them
}