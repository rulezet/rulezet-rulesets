rule TTP_XOR_MULT_DOSStub_eef6 {
  strings:
    $key_eef6 = { ba 9e [2] ce 86 [2] 89 84 [2] ce 95 [2] 80 99 [2] 8c 93 [2] 9b 98 [2] 80 d6 [2] bd }

  condition:
    any of them
}