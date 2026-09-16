rule TTP_XOR_MULT_DOSStub_21f4 {
  strings:
    $key_21f4 = { 75 9c [2] 01 84 [2] 46 86 [2] 01 97 [2] 4f 9b [2] 43 91 [2] 54 9a [2] 4f d4 [2] 72 }

  condition:
    any of them
}