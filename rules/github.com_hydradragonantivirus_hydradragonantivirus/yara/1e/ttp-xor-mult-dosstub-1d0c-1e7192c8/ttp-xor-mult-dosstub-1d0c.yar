rule TTP_XOR_MULT_DOSStub_1d0c {
  strings:
    $key_1d0c = { 49 64 [2] 3d 7c [2] 7a 7e [2] 3d 6f [2] 73 63 [2] 7f 69 [2] 68 62 [2] 73 2c [2] 4e }

  condition:
    any of them
}