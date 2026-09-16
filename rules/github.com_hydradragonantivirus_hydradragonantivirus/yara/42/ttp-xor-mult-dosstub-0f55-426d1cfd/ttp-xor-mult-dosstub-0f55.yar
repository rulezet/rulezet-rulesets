rule TTP_XOR_MULT_DOSStub_0f55 {
  strings:
    $key_0f55 = { 5b 3d [2] 2f 25 [2] 68 27 [2] 2f 36 [2] 61 3a [2] 6d 30 [2] 7a 3b [2] 61 75 [2] 5c }

  condition:
    any of them
}