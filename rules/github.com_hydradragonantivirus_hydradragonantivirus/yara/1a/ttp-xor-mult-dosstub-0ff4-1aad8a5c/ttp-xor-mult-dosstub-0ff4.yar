rule TTP_XOR_MULT_DOSStub_0ff4 {
  strings:
    $key_0ff4 = { 5b 9c [2] 2f 84 [2] 68 86 [2] 2f 97 [2] 61 9b [2] 6d 91 [2] 7a 9a [2] 61 d4 [2] 5c }

  condition:
    any of them
}