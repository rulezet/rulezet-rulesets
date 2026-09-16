rule TTP_XOR_MULT_DOSStub_2ff4 {
  strings:
    $key_2ff4 = { 7b 9c [2] 0f 84 [2] 48 86 [2] 0f 97 [2] 41 9b [2] 4d 91 [2] 5a 9a [2] 41 d4 [2] 7c }

  condition:
    any of them
}