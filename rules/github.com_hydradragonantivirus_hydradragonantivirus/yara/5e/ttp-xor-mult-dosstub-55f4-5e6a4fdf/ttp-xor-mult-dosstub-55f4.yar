rule TTP_XOR_MULT_DOSStub_55f4 {
  strings:
    $key_55f4 = { 01 9c [2] 75 84 [2] 32 86 [2] 75 97 [2] 3b 9b [2] 37 91 [2] 20 9a [2] 3b d4 [2] 06 }

  condition:
    any of them
}