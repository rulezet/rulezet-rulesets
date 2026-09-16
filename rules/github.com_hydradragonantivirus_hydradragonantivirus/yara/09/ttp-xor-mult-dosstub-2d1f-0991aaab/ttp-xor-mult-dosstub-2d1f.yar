rule TTP_XOR_MULT_DOSStub_2d1f {
  strings:
    $key_2d1f = { 79 77 [2] 0d 6f [2] 4a 6d [2] 0d 7c [2] 43 70 [2] 4f 7a [2] 58 71 [2] 43 3f [2] 7e }

  condition:
    any of them
}