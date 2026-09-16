rule TTP_XOR_MULT_DOSStub_2e7f {
  strings:
    $key_2e7f = { 7a 17 [2] 0e 0f [2] 49 0d [2] 0e 1c [2] 40 10 [2] 4c 1a [2] 5b 11 [2] 40 5f [2] 7d }

  condition:
    any of them
}