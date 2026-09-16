rule TTP_XOR_MULT_DOSStub_5e6f {
  strings:
    $key_5e6f = { 0a 07 [2] 7e 1f [2] 39 1d [2] 7e 0c [2] 30 00 [2] 3c 0a [2] 2b 01 [2] 30 4f [2] 0d }

  condition:
    any of them
}