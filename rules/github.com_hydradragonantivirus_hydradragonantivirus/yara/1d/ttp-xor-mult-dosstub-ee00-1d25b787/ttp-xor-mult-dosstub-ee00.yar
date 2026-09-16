rule TTP_XOR_MULT_DOSStub_ee00 {
  strings:
    $key_ee00 = { ba 68 [2] ce 70 [2] 89 72 [2] ce 63 [2] 80 6f [2] 8c 65 [2] 9b 6e [2] 80 20 [2] bd }

  condition:
    any of them
}