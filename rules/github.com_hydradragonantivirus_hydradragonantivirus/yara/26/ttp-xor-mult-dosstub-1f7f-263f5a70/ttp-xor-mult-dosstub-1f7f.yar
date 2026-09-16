rule TTP_XOR_MULT_DOSStub_1f7f {
  strings:
    $key_1f7f = { 4b 17 [2] 3f 0f [2] 78 0d [2] 3f 1c [2] 71 10 [2] 7d 1a [2] 6a 11 [2] 71 5f [2] 4c }

  condition:
    any of them
}