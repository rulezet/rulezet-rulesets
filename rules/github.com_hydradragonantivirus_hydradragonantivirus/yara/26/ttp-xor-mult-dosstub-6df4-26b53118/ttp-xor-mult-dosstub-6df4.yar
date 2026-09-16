rule TTP_XOR_MULT_DOSStub_6df4 {
  strings:
    $key_6df4 = { 39 9c [2] 4d 84 [2] 0a 86 [2] 4d 97 [2] 03 9b [2] 0f 91 [2] 18 9a [2] 03 d4 [2] 3e }

  condition:
    any of them
}