rule TTP_XOR_MULT_DOSStub_ee02 {
  strings:
    $key_ee02 = { ba 6a [2] ce 72 [2] 89 70 [2] ce 61 [2] 80 6d [2] 8c 67 [2] 9b 6c [2] 80 22 [2] bd }

  condition:
    any of them
}