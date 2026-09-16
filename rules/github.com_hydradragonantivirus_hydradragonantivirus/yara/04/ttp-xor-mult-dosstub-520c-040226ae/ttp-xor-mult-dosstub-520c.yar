rule TTP_XOR_MULT_DOSStub_520c {
  strings:
    $key_520c = { 06 64 [2] 72 7c [2] 35 7e [2] 72 6f [2] 3c 63 [2] 30 69 [2] 27 62 [2] 3c 2c [2] 01 }

  condition:
    any of them
}