rule TTP_XOR_MULT_DOSStub_eee3 {
  strings:
    $key_eee3 = { ba 8b [2] ce 93 [2] 89 91 [2] ce 80 [2] 80 8c [2] 8c 86 [2] 9b 8d [2] 80 c3 [2] bd }

  condition:
    any of them
}