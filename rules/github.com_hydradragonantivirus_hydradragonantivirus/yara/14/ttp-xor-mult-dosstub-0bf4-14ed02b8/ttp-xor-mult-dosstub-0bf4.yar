rule TTP_XOR_MULT_DOSStub_0bf4 {
  strings:
    $key_0bf4 = { 5f 9c [2] 2b 84 [2] 6c 86 [2] 2b 97 [2] 65 9b [2] 69 91 [2] 7e 9a [2] 65 d4 [2] 58 }

  condition:
    any of them
}