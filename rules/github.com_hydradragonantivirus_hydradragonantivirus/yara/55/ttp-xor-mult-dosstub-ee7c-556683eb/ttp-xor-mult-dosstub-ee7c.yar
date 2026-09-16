rule TTP_XOR_MULT_DOSStub_ee7c {
  strings:
    $key_ee7c = { ba 14 [2] ce 0c [2] 89 0e [2] ce 1f [2] 80 13 [2] 8c 19 [2] 9b 12 [2] 80 5c [2] bd }

  condition:
    any of them
}