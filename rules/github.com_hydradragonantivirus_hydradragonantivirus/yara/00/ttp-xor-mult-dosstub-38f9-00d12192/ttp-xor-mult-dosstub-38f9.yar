rule TTP_XOR_MULT_DOSStub_38f9 {
  strings:
    $key_38f9 = { 6c 91 [2] 18 89 [2] 5f 8b [2] 18 9a [2] 56 96 [2] 5a 9c [2] 4d 97 [2] 56 d9 [2] 6b }

  condition:
    any of them
}