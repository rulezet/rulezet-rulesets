rule TTP_XOR_MULT_DOSStub_ee70 {
  strings:
    $key_ee70 = { ba 18 [2] ce 00 [2] 89 02 [2] ce 13 [2] 80 1f [2] 8c 15 [2] 9b 1e [2] 80 50 [2] bd }

  condition:
    any of them
}