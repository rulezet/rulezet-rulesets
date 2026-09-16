rule TTP_XOR_MULT_DOSStub_3f3f {
  strings:
    $key_3f3f = { 6b 57 [2] 1f 4f [2] 58 4d [2] 1f 5c [2] 51 50 [2] 5d 5a [2] 4a 51 [2] 51 1f [2] 6c }

  condition:
    any of them
}