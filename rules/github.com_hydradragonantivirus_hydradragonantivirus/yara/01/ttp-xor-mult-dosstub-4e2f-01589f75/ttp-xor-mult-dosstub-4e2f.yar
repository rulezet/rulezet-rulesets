rule TTP_XOR_MULT_DOSStub_4e2f {
  strings:
    $key_4e2f = { 1a 47 [2] 6e 5f [2] 29 5d [2] 6e 4c [2] 20 40 [2] 2c 4a [2] 3b 41 [2] 20 0f [2] 1d }

  condition:
    any of them
}