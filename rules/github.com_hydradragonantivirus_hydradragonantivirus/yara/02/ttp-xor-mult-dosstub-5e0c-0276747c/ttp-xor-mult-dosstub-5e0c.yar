rule TTP_XOR_MULT_DOSStub_5e0c {
  strings:
    $key_5e0c = { 0a 64 [2] 7e 7c [2] 39 7e [2] 7e 6f [2] 30 63 [2] 3c 69 [2] 2b 62 [2] 30 2c [2] 0d }

  condition:
    any of them
}