rule TTP_XOR_MULT_DOSStub_390c {
  strings:
    $key_390c = { 6d 64 [2] 19 7c [2] 5e 7e [2] 19 6f [2] 57 63 [2] 5b 69 [2] 4c 62 [2] 57 2c [2] 6a }

  condition:
    any of them
}