rule TTP_XOR_MULT_DOSStub_786f {
  strings:
    $key_786f = { 2c 07 [2] 58 1f [2] 1f 1d [2] 58 0c [2] 16 00 [2] 1a 0a [2] 0d 01 [2] 16 4f [2] 2b }

  condition:
    any of them
}