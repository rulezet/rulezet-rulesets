rule TTP_XOR_MULT_DOSStub_2ff9 {
  strings:
    $key_2ff9 = { 7b 91 [2] 0f 89 [2] 48 8b [2] 0f 9a [2] 41 96 [2] 4d 9c [2] 5a 97 [2] 41 d9 [2] 7c }

  condition:
    any of them
}