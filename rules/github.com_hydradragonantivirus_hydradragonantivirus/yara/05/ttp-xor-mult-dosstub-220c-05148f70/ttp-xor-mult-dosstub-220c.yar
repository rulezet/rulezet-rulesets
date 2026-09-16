rule TTP_XOR_MULT_DOSStub_220c {
  strings:
    $key_220c = { 76 64 [2] 02 7c [2] 45 7e [2] 02 6f [2] 4c 63 [2] 40 69 [2] 57 62 [2] 4c 2c [2] 71 }

  condition:
    any of them
}