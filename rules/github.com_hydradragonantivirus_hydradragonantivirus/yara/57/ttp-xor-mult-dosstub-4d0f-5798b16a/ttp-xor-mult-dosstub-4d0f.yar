rule TTP_XOR_MULT_DOSStub_4d0f {
  strings:
    $key_4d0f = { 19 67 [2] 6d 7f [2] 2a 7d [2] 6d 6c [2] 23 60 [2] 2f 6a [2] 38 61 [2] 23 2f [2] 1e }

  condition:
    any of them
}