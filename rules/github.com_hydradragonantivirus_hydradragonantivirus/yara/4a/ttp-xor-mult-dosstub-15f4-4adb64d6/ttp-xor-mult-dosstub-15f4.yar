rule TTP_XOR_MULT_DOSStub_15f4 {
  strings:
    $key_15f4 = { 41 9c [2] 35 84 [2] 72 86 [2] 35 97 [2] 7b 9b [2] 77 91 [2] 60 9a [2] 7b d4 [2] 46 }

  condition:
    any of them
}