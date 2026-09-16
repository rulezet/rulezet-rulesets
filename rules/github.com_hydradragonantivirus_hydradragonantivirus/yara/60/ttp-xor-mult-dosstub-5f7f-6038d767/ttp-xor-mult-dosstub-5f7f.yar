rule TTP_XOR_MULT_DOSStub_5f7f {
  strings:
    $key_5f7f = { 0b 17 [2] 7f 0f [2] 38 0d [2] 7f 1c [2] 31 10 [2] 3d 1a [2] 2a 11 [2] 31 5f [2] 0c }

  condition:
    any of them
}