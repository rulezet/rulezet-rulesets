rule TTP_XOR_MULT_DOSStub_55f2 {
  strings:
    $key_55f2 = { 01 9a [2] 75 82 [2] 32 80 [2] 75 91 [2] 3b 9d [2] 37 97 [2] 20 9c [2] 3b d2 [2] 06 }

  condition:
    any of them
}