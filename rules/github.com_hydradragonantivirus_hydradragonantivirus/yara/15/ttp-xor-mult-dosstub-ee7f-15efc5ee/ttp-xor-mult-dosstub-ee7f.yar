rule TTP_XOR_MULT_DOSStub_ee7f {
  strings:
    $key_ee7f = { ba 17 [2] ce 0f [2] 89 0d [2] ce 1c [2] 80 10 [2] 8c 1a [2] 9b 11 [2] 80 5f [2] bd }

  condition:
    any of them
}