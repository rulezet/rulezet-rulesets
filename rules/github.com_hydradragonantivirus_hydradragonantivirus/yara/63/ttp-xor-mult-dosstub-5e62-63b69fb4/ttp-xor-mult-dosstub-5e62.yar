rule TTP_XOR_MULT_DOSStub_5e62 {
  strings:
    $key_5e62 = { 0a 0a [2] 7e 12 [2] 39 10 [2] 7e 01 [2] 30 0d [2] 3c 07 [2] 2b 0c [2] 30 42 [2] 0d }

  condition:
    any of them
}