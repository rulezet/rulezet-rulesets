rule TTP_XOR_MULT_DOSStub_ee62 {
  strings:
    $key_ee62 = { ba 0a [2] ce 12 [2] 89 10 [2] ce 01 [2] 80 0d [2] 8c 07 [2] 9b 0c [2] 80 42 [2] bd }

  condition:
    any of them
}