rule TTP_XOR_MULT_DOSStub_ee7d {
  strings:
    $key_ee7d = { ba 15 [2] ce 0d [2] 89 0f [2] ce 1e [2] 80 12 [2] 8c 18 [2] 9b 13 [2] 80 5d [2] bd }

  condition:
    any of them
}