rule TTP_XOR_MULT_DOSStub_0b4d {
  strings:
    $key_0b4d = { 5f 25 [2] 2b 3d [2] 6c 3f [2] 2b 2e [2] 65 22 [2] 69 28 [2] 7e 23 [2] 65 6d [2] 58 }

  condition:
    any of them
}