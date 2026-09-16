rule TTP_XOR_MULT_DOSStub_1a0f {
  strings:
    $key_1a0f = { 4e 67 [2] 3a 7f [2] 7d 7d [2] 3a 6c [2] 74 60 [2] 78 6a [2] 6f 61 [2] 74 2f [2] 49 }

  condition:
    any of them
}