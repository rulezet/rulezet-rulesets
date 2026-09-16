rule TTP_XOR_MULT_DOSStub_5f3f {
  strings:
    $key_5f3f = { 0b 57 [2] 7f 4f [2] 38 4d [2] 7f 5c [2] 31 50 [2] 3d 5a [2] 2a 51 [2] 31 1f [2] 0c }

  condition:
    any of them
}