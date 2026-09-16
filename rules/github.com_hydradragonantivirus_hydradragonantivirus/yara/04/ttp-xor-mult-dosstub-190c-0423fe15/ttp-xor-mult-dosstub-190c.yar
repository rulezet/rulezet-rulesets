rule TTP_XOR_MULT_DOSStub_190c {
  strings:
    $key_190c = { 4d 64 [2] 39 7c [2] 7e 7e [2] 39 6f [2] 77 63 [2] 7b 69 [2] 6c 62 [2] 77 2c [2] 4a }

  condition:
    any of them
}