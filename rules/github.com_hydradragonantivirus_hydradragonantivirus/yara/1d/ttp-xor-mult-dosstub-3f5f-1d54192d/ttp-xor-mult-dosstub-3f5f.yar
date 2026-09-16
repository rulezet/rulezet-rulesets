rule TTP_XOR_MULT_DOSStub_3f5f {
  strings:
    $key_3f5f = { 6b 37 [2] 1f 2f [2] 58 2d [2] 1f 3c [2] 51 30 [2] 5d 3a [2] 4a 31 [2] 51 7f [2] 6c }

  condition:
    any of them
}