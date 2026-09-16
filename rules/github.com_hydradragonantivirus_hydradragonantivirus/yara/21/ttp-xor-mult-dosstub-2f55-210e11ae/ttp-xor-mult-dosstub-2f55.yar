rule TTP_XOR_MULT_DOSStub_2f55 {
  strings:
    $key_2f55 = { 7b 3d [2] 0f 25 [2] 48 27 [2] 0f 36 [2] 41 3a [2] 4d 30 [2] 5a 3b [2] 41 75 [2] 7c }

  condition:
    any of them
}