rule TTP_XOR_MULT_DOSStub_4a0f {
  strings:
    $key_4a0f = { 1e 67 [2] 6a 7f [2] 2d 7d [2] 6a 6c [2] 24 60 [2] 28 6a [2] 3f 61 [2] 24 2f [2] 19 }

  condition:
    any of them
}