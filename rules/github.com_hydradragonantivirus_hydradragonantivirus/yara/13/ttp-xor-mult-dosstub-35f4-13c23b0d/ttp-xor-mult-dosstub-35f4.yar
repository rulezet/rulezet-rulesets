rule TTP_XOR_MULT_DOSStub_35f4 {
  strings:
    $key_35f4 = { 61 9c [2] 15 84 [2] 52 86 [2] 15 97 [2] 5b 9b [2] 57 91 [2] 40 9a [2] 5b d4 [2] 66 }

  condition:
    any of them
}