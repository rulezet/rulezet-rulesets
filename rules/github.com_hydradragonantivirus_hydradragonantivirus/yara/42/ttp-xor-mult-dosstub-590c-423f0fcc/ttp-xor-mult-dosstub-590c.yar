rule TTP_XOR_MULT_DOSStub_590c {
  strings:
    $key_590c = { 0d 64 [2] 79 7c [2] 3e 7e [2] 79 6f [2] 37 63 [2] 3b 69 [2] 2c 62 [2] 37 2c [2] 0a }

  condition:
    any of them
}