rule TTP_XOR_MULT_DOSStub_6ff4 {
  strings:
    $key_6ff4 = { 3b 9c [2] 4f 84 [2] 08 86 [2] 4f 97 [2] 01 9b [2] 0d 91 [2] 1a 9a [2] 01 d4 [2] 3c }

  condition:
    any of them
}