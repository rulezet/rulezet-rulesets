rule TTP_XOR_MULT_DOSStub_2e6f {
  strings:
    $key_2e6f = { 7a 07 [2] 0e 1f [2] 49 1d [2] 0e 0c [2] 40 00 [2] 4c 0a [2] 5b 01 [2] 40 4f [2] 7d }

  condition:
    any of them
}