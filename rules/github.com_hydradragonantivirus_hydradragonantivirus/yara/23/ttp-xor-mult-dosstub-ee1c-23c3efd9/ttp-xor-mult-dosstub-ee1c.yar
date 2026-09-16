rule TTP_XOR_MULT_DOSStub_ee1c {
  strings:
    $key_ee1c = { ba 74 [2] ce 6c [2] 89 6e [2] ce 7f [2] 80 73 [2] 8c 79 [2] 9b 72 [2] 80 3c [2] bd }

  condition:
    any of them
}