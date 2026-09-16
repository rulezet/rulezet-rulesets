rule TTP_XOR_MULT_DOSStub_eef2 {
  strings:
    $key_eef2 = { ba 9a [2] ce 82 [2] 89 80 [2] ce 91 [2] 80 9d [2] 8c 97 [2] 9b 9c [2] 80 d2 [2] bd }

  condition:
    any of them
}