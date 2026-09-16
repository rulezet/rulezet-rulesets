rule TTP_XOR_MULT_DOSStub_52f4 {
  strings:
    $key_52f4 = { 06 9c [2] 72 84 [2] 35 86 [2] 72 97 [2] 3c 9b [2] 30 91 [2] 27 9a [2] 3c d4 [2] 01 }

  condition:
    any of them
}