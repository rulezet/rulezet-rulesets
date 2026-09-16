rule TTP_XOR_MULT_DOSStub_485c {
  strings:
    $key_485c = { 1c 34 [2] 68 2c [2] 2f 2e [2] 68 3f [2] 26 33 [2] 2a 39 [2] 3d 32 [2] 26 7c [2] 1b }

  condition:
    any of them
}