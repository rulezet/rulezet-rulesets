rule TTP_XOR_MULT_DOSStub_1bf4 {
  strings:
    $key_1bf4 = { 4f 9c [2] 3b 84 [2] 7c 86 [2] 3b 97 [2] 75 9b [2] 79 91 [2] 6e 9a [2] 75 d4 [2] 48 }

  condition:
    any of them
}