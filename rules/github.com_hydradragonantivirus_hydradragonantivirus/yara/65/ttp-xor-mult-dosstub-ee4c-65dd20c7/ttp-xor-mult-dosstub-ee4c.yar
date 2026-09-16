rule TTP_XOR_MULT_DOSStub_ee4c {
  strings:
    $key_ee4c = { ba 24 [2] ce 3c [2] 89 3e [2] ce 2f [2] 80 23 [2] 8c 29 [2] 9b 22 [2] 80 6c [2] bd }

  condition:
    any of them
}