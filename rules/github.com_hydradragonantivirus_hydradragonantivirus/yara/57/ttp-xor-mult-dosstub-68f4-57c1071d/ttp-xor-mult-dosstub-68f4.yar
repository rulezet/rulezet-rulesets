rule TTP_XOR_MULT_DOSStub_68f4 {
  strings:
    $key_68f4 = { 3c 9c [2] 48 84 [2] 0f 86 [2] 48 97 [2] 06 9b [2] 0a 91 [2] 1d 9a [2] 06 d4 [2] 3b }

  condition:
    any of them
}