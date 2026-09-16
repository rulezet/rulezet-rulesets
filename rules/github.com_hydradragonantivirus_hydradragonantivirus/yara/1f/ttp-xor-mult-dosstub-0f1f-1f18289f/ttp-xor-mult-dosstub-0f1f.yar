rule TTP_XOR_MULT_DOSStub_0f1f {
  strings:
    $key_0f1f = { 5b 77 [2] 2f 6f [2] 68 6d [2] 2f 7c [2] 61 70 [2] 6d 7a [2] 7a 71 [2] 61 3f [2] 5c }

  condition:
    any of them
}