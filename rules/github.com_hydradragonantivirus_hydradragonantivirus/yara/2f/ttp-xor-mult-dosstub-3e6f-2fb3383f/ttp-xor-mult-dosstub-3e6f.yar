rule TTP_XOR_MULT_DOSStub_3e6f {
  strings:
    $key_3e6f = { 6a 07 [2] 1e 1f [2] 59 1d [2] 1e 0c [2] 50 00 [2] 5c 0a [2] 4b 01 [2] 50 4f [2] 6d }

  condition:
    any of them
}