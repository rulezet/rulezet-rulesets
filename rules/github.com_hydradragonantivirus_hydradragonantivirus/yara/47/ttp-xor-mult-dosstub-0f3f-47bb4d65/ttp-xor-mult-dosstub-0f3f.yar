rule TTP_XOR_MULT_DOSStub_0f3f {
  strings:
    $key_0f3f = { 5b 57 [2] 2f 4f [2] 68 4d [2] 2f 5c [2] 61 50 [2] 6d 5a [2] 7a 51 [2] 61 1f [2] 5c }

  condition:
    any of them
}