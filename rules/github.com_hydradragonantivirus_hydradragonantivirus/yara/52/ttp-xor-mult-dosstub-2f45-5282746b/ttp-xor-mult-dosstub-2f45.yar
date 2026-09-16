rule TTP_XOR_MULT_DOSStub_2f45 {
  strings:
    $key_2f45 = { 7b 2d [2] 0f 35 [2] 48 37 [2] 0f 26 [2] 41 2a [2] 4d 20 [2] 5a 2b [2] 41 65 [2] 7c }

  condition:
    any of them
}