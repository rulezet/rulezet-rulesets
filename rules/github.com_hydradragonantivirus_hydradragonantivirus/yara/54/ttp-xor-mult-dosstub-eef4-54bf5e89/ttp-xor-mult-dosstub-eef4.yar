rule TTP_XOR_MULT_DOSStub_eef4 {
  strings:
    $key_eef4 = { ba 9c [2] ce 84 [2] 89 86 [2] ce 97 [2] 80 9b [2] 8c 91 [2] 9b 9a [2] 80 d4 [2] bd }

  condition:
    any of them
}