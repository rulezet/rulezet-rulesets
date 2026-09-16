rule TTP_XOR_MULT_DOSStub_360c {
  strings:
    $key_360c = { 62 64 [2] 16 7c [2] 51 7e [2] 16 6f [2] 58 63 [2] 54 69 [2] 43 62 [2] 58 2c [2] 65 }

  condition:
    any of them
}