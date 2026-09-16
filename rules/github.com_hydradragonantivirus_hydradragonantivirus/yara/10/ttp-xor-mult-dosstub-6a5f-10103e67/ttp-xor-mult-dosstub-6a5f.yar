rule TTP_XOR_MULT_DOSStub_6a5f {
  strings:
    $key_6a5f = { 3e 37 [2] 4a 2f [2] 0d 2d [2] 4a 3c [2] 04 30 [2] 08 3a [2] 1f 31 [2] 04 7f [2] 39 }

  condition:
    any of them
}