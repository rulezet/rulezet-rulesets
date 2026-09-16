rule TTP_XOR_MULT_DOSStub_00f4 {
  strings:
    $key_00f4 = { 54 9c [2] 20 84 [2] 67 86 [2] 20 97 [2] 6e 9b [2] 62 91 [2] 75 9a [2] 6e d4 [2] 53 }

  condition:
    any of them
}