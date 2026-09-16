rule TTP_XOR_MULT_DOSStub_ee3a {
  strings:
    $key_ee3a = { ba 52 [2] ce 4a [2] 89 48 [2] ce 59 [2] 80 55 [2] 8c 5f [2] 9b 54 [2] 80 1a [2] bd }

  condition:
    any of them
}