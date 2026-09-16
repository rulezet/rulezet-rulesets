rule TTP_XOR_MULT_DOSStub_ee64 {
  strings:
    $key_ee64 = { ba 0c [2] ce 14 [2] 89 16 [2] ce 07 [2] 80 0b [2] 8c 01 [2] 9b 0a [2] 80 44 [2] bd }

  condition:
    any of them
}