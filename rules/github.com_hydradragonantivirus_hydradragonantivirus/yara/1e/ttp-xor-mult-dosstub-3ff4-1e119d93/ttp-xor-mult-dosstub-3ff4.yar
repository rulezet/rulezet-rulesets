rule TTP_XOR_MULT_DOSStub_3ff4 {
  strings:
    $key_3ff4 = { 6b 9c [2] 1f 84 [2] 58 86 [2] 1f 97 [2] 51 9b [2] 5d 91 [2] 4a 9a [2] 51 d4 [2] 6c }

  condition:
    any of them
}