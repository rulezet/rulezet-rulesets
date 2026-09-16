rule TTP_XOR_MULT_DOSStub_36f4 {
  strings:
    $key_36f4 = { 62 9c [2] 16 84 [2] 51 86 [2] 16 97 [2] 58 9b [2] 54 91 [2] 43 9a [2] 58 d4 [2] 65 }

  condition:
    any of them
}