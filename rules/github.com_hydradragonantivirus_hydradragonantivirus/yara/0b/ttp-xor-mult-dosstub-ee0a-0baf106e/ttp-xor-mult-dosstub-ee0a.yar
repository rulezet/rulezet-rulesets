rule TTP_XOR_MULT_DOSStub_ee0a {
  strings:
    $key_ee0a = { ba 62 [2] ce 7a [2] 89 78 [2] ce 69 [2] 80 65 [2] 8c 6f [2] 9b 64 [2] 80 2a [2] bd }

  condition:
    any of them
}