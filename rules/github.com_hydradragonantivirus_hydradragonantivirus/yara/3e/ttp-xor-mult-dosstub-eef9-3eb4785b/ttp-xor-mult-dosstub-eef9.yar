rule TTP_XOR_MULT_DOSStub_eef9 {
  strings:
    $key_eef9 = { ba 91 [2] ce 89 [2] 89 8b [2] ce 9a [2] 80 96 [2] 8c 9c [2] 9b 97 [2] 80 d9 [2] bd }

  condition:
    any of them
}