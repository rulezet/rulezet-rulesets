rule TTP_XOR_MULT_DOSStub_2f25 {
  strings:
    $key_2f25 = { 7b 4d [2] 0f 55 [2] 48 57 [2] 0f 46 [2] 41 4a [2] 4d 40 [2] 5a 4b [2] 41 05 [2] 7c }

  condition:
    any of them
}