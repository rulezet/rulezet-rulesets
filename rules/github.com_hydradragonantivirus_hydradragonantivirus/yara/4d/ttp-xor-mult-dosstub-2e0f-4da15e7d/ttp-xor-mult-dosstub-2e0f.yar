rule TTP_XOR_MULT_DOSStub_2e0f {
  strings:
    $key_2e0f = { 7a 67 [2] 0e 7f [2] 49 7d [2] 0e 6c [2] 40 60 [2] 4c 6a [2] 5b 61 [2] 40 2f [2] 7d }

  condition:
    any of them
}