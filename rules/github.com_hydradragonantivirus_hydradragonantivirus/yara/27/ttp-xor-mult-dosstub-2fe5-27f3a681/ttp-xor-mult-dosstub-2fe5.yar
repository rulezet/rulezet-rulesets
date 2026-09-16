rule TTP_XOR_MULT_DOSStub_2fe5 {
  strings:
    $key_2fe5 = { 7b 8d [2] 0f 95 [2] 48 97 [2] 0f 86 [2] 41 8a [2] 4d 80 [2] 5a 8b [2] 41 c5 [2] 7c }

  condition:
    any of them
}