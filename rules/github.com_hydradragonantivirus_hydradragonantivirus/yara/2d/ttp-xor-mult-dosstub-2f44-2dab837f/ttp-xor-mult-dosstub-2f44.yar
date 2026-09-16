rule TTP_XOR_MULT_DOSStub_2f44 {
  strings:
    $key_2f44 = { 7b 2c [2] 0f 34 [2] 48 36 [2] 0f 27 [2] 41 2b [2] 4d 21 [2] 5a 2a [2] 41 64 [2] 7c }

  condition:
    any of them
}