rule TTP_XOR_MULT_DOSStub_4e0f {
  strings:
    $key_4e0f = { 1a 67 [2] 6e 7f [2] 29 7d [2] 6e 6c [2] 20 60 [2] 2c 6a [2] 3b 61 [2] 20 2f [2] 1d }

  condition:
    any of them
}