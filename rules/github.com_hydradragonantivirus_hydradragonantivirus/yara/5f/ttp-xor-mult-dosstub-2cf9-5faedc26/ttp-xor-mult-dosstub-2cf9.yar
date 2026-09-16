rule TTP_XOR_MULT_DOSStub_2cf9 {
  strings:
    $key_2cf9 = { 78 91 [2] 0c 89 [2] 4b 8b [2] 0c 9a [2] 42 96 [2] 4e 9c [2] 59 97 [2] 42 d9 [2] 7f }

  condition:
    any of them
}