rule TTP_XOR_MULT_DOSStub_ee22 {
  strings:
    $key_ee22 = { ba 4a [2] ce 52 [2] 89 50 [2] ce 41 [2] 80 4d [2] 8c 47 [2] 9b 4c [2] 80 02 [2] bd }

  condition:
    any of them
}