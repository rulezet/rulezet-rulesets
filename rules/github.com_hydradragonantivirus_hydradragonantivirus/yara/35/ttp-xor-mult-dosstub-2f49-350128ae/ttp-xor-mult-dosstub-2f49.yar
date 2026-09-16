rule TTP_XOR_MULT_DOSStub_2f49 {
  strings:
    $key_2f49 = { 7b 21 [2] 0f 39 [2] 48 3b [2] 0f 2a [2] 41 26 [2] 4d 2c [2] 5a 27 [2] 41 69 [2] 7c }

  condition:
    any of them
}