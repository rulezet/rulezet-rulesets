rule TTP_XOR_MULT_DOSStub_0d0c {
  strings:
    $key_0d0c = { 59 64 [2] 2d 7c [2] 6a 7e [2] 2d 6f [2] 63 63 [2] 6f 69 [2] 78 62 [2] 63 2c [2] 5e }

  condition:
    any of them
}