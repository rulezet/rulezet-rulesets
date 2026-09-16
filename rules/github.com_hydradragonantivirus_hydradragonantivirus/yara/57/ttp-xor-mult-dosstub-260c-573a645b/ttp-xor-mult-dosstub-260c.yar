rule TTP_XOR_MULT_DOSStub_260c {
  strings:
    $key_260c = { 72 64 [2] 06 7c [2] 41 7e [2] 06 6f [2] 48 63 [2] 44 69 [2] 53 62 [2] 48 2c [2] 75 }

  condition:
    any of them
}