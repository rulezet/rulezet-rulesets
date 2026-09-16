rule TTP_XOR_MULT_DOSStub_2f04 {
  strings:
    $key_2f04 = { 7b 6c [2] 0f 74 [2] 48 76 [2] 0f 67 [2] 41 6b [2] 4d 61 [2] 5a 6a [2] 41 24 [2] 7c }

  condition:
    any of them
}