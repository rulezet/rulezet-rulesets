rule TTP_XOR_MULT_DOSStub_25f4 {
  strings:
    $key_25f4 = { 71 9c [2] 05 84 [2] 42 86 [2] 05 97 [2] 4b 9b [2] 47 91 [2] 50 9a [2] 4b d4 [2] 76 }

  condition:
    any of them
}