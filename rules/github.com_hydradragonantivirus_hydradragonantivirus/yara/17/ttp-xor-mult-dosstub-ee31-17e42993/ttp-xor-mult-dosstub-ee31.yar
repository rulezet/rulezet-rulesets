rule TTP_XOR_MULT_DOSStub_ee31 {
  strings:
    $key_ee31 = { ba 59 [2] ce 41 [2] 89 43 [2] ce 52 [2] 80 5e [2] 8c 54 [2] 9b 5f [2] 80 11 [2] bd }

  condition:
    any of them
}