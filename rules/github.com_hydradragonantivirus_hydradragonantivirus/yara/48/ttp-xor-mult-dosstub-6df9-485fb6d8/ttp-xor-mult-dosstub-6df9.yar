rule TTP_XOR_MULT_DOSStub_6df9 {
  strings:
    $key_6df9 = { 39 91 [2] 4d 89 [2] 0a 8b [2] 4d 9a [2] 03 96 [2] 0f 9c [2] 18 97 [2] 03 d9 [2] 3e }

  condition:
    any of them
}