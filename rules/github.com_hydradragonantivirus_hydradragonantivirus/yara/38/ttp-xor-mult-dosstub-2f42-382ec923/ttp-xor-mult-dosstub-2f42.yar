rule TTP_XOR_MULT_DOSStub_2f42 {
  strings:
    $key_2f42 = { 7b 2a [2] 0f 32 [2] 48 30 [2] 0f 21 [2] 41 2d [2] 4d 27 [2] 5a 2c [2] 41 62 [2] 7c }

  condition:
    any of them
}