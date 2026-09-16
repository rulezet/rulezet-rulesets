rule TTP_XOR_MULT_DOSStub_2d0c {
  strings:
    $key_2d0c = { 79 64 [2] 0d 7c [2] 4a 7e [2] 0d 6f [2] 43 63 [2] 4f 69 [2] 58 62 [2] 43 2c [2] 7e }

  condition:
    any of them
}