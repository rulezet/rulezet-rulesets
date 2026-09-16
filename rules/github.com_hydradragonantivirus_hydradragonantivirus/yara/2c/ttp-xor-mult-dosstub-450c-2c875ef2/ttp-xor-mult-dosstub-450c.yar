rule TTP_XOR_MULT_DOSStub_450c {
  strings:
    $key_450c = { 11 64 [2] 65 7c [2] 22 7e [2] 65 6f [2] 2b 63 [2] 27 69 [2] 30 62 [2] 2b 2c [2] 16 }

  condition:
    any of them
}