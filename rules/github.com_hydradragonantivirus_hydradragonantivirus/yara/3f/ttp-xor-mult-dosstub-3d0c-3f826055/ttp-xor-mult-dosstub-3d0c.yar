rule TTP_XOR_MULT_DOSStub_3d0c {
  strings:
    $key_3d0c = { 69 64 [2] 1d 7c [2] 5a 7e [2] 1d 6f [2] 53 63 [2] 5f 69 [2] 48 62 [2] 53 2c [2] 6e }

  condition:
    any of them
}