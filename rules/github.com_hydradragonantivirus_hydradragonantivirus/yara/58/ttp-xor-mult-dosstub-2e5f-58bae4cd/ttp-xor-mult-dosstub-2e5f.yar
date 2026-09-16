rule TTP_XOR_MULT_DOSStub_2e5f {
  strings:
    $key_2e5f = { 7a 37 [2] 0e 2f [2] 49 2d [2] 0e 3c [2] 40 30 [2] 4c 3a [2] 5b 31 [2] 40 7f [2] 7d }

  condition:
    any of them
}