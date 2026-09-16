rule TTP_XOR_MULT_DOSStub_62f4 {
  strings:
    $key_62f4 = { 36 9c [2] 42 84 [2] 05 86 [2] 42 97 [2] 0c 9b [2] 00 91 [2] 17 9a [2] 0c d4 [2] 31 }

  condition:
    any of them
}