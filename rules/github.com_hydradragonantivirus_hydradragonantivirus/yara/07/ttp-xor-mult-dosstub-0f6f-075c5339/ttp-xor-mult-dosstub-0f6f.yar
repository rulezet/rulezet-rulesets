rule TTP_XOR_MULT_DOSStub_0f6f {
  strings:
    $key_0f6f = { 5b 07 [2] 2f 1f [2] 68 1d [2] 2f 0c [2] 61 00 [2] 6d 0a [2] 7a 01 [2] 61 4f [2] 5c }

  condition:
    any of them
}