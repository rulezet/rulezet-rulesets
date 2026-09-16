rule TTP_XOR_MULT_DOSStub_5901 {
  strings:
    $key_5901 = { 0d 69 [2] 79 71 [2] 3e 73 [2] 79 62 [2] 37 6e [2] 3b 64 [2] 2c 6f [2] 37 21 [2] 0a }

  condition:
    any of them
}