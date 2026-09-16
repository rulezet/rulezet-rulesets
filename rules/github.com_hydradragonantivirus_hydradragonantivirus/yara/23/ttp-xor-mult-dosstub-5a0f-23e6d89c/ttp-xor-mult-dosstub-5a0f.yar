rule TTP_XOR_MULT_DOSStub_5a0f {
  strings:
    $key_5a0f = { 0e 67 [2] 7a 7f [2] 3d 7d [2] 7a 6c [2] 34 60 [2] 38 6a [2] 2f 61 [2] 34 2f [2] 09 }

  condition:
    any of them
}