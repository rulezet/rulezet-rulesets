rule TTP_XOR_MULT_DOSStub_eee0 {
  strings:
    $key_eee0 = { ba 88 [2] ce 90 [2] 89 92 [2] ce 83 [2] 80 8f [2] 8c 85 [2] 9b 8e [2] 80 c0 [2] bd }

  condition:
    any of them
}