rule TTP_XOR_MULT_DOSStub_3bf4 {
  strings:
    $key_3bf4 = { 6f 9c [2] 1b 84 [2] 5c 86 [2] 1b 97 [2] 55 9b [2] 59 91 [2] 4e 9a [2] 55 d4 [2] 68 }

  condition:
    any of them
}