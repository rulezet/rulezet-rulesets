rule TTP_XOR_MULT_DOSStub_4c0c {
  strings:
    $key_4c0c = { 18 64 [2] 6c 7c [2] 2b 7e [2] 6c 6f [2] 22 63 [2] 2e 69 [2] 39 62 [2] 22 2c [2] 1f }

  condition:
    any of them
}