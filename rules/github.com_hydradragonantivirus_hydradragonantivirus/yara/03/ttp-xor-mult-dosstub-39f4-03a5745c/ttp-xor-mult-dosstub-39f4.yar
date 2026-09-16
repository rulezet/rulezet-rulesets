rule TTP_XOR_MULT_DOSStub_39f4 {
  strings:
    $key_39f4 = { 6d 9c [2] 19 84 [2] 5e 86 [2] 19 97 [2] 57 9b [2] 5b 91 [2] 4c 9a [2] 57 d4 [2] 6a }

  condition:
    any of them
}