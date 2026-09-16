rule TTP_XOR_MULT_DOSStub_74f4 {
  strings:
    $key_74f4 = { 20 9c [2] 54 84 [2] 13 86 [2] 54 97 [2] 1a 9b [2] 16 91 [2] 01 9a [2] 1a d4 [2] 27 }

  condition:
    any of them
}