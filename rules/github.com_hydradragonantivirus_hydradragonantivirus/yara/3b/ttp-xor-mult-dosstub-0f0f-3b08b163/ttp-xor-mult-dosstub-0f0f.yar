rule TTP_XOR_MULT_DOSStub_0f0f {
  strings:
    $key_0f0f = { 5b 67 [2] 2f 7f [2] 68 7d [2] 2f 6c [2] 61 60 [2] 6d 6a [2] 7a 61 [2] 61 2f [2] 5c }

  condition:
    any of them
}