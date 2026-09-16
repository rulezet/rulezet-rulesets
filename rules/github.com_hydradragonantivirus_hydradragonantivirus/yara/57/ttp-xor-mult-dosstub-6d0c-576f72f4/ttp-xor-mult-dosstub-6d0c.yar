rule TTP_XOR_MULT_DOSStub_6d0c {
  strings:
    $key_6d0c = { 39 64 [2] 4d 7c [2] 0a 7e [2] 4d 6f [2] 03 63 [2] 0f 69 [2] 18 62 [2] 03 2c [2] 3e }

  condition:
    any of them
}