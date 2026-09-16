rule TTP_XOR_MULT_DOSStub_5bf4 {
  strings:
    $key_5bf4 = { 0f 9c [2] 7b 84 [2] 3c 86 [2] 7b 97 [2] 35 9b [2] 39 91 [2] 2e 9a [2] 35 d4 [2] 08 }

  condition:
    any of them
}