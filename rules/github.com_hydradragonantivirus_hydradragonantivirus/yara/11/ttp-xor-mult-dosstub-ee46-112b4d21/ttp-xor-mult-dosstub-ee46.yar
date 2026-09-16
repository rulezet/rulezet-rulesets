rule TTP_XOR_MULT_DOSStub_ee46 {
  strings:
    $key_ee46 = { ba 2e [2] ce 36 [2] 89 34 [2] ce 25 [2] 80 29 [2] 8c 23 [2] 9b 28 [2] 80 66 [2] bd }

  condition:
    any of them
}