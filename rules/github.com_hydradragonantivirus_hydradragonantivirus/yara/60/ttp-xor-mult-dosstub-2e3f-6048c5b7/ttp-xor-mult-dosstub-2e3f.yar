rule TTP_XOR_MULT_DOSStub_2e3f {
  strings:
    $key_2e3f = { 7a 57 [2] 0e 4f [2] 49 4d [2] 0e 5c [2] 40 50 [2] 4c 5a [2] 5b 51 [2] 40 1f [2] 7d }

  condition:
    any of them
}