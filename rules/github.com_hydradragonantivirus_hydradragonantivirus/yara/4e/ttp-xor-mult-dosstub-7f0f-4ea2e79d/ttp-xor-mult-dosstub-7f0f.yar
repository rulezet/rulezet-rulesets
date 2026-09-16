rule TTP_XOR_MULT_DOSStub_7f0f {
  strings:
    $key_7f0f = { 2b 67 [2] 5f 7f [2] 18 7d [2] 5f 6c [2] 11 60 [2] 1d 6a [2] 0a 61 [2] 11 2f [2] 2c }

  condition:
    any of them
}