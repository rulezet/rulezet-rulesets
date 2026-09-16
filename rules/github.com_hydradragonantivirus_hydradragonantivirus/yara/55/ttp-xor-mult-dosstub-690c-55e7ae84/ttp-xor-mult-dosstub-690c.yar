rule TTP_XOR_MULT_DOSStub_690c {
  strings:
    $key_690c = { 3d 64 [2] 49 7c [2] 0e 7e [2] 49 6f [2] 07 63 [2] 0b 69 [2] 1c 62 [2] 07 2c [2] 3a }

  condition:
    any of them
}