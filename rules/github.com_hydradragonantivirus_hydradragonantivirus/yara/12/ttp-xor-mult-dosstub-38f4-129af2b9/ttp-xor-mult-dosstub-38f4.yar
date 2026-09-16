rule TTP_XOR_MULT_DOSStub_38f4 {
  strings:
    $key_38f4 = { 6c 9c [2] 18 84 [2] 5f 86 [2] 18 97 [2] 56 9b [2] 5a 91 [2] 4d 9a [2] 56 d4 [2] 6b }

  condition:
    any of them
}