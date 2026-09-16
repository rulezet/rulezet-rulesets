rule TTP_XOR_MULT_DOSStub_7a0f {
  strings:
    $key_7a0f = { 2e 67 [2] 5a 7f [2] 1d 7d [2] 5a 6c [2] 14 60 [2] 18 6a [2] 0f 61 [2] 14 2f [2] 29 }

  condition:
    any of them
}