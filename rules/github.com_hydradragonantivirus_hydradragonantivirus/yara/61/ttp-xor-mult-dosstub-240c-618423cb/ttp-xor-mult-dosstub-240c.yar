rule TTP_XOR_MULT_DOSStub_240c {
  strings:
    $key_240c = { 70 64 [2] 04 7c [2] 43 7e [2] 04 6f [2] 4a 63 [2] 46 69 [2] 51 62 [2] 4a 2c [2] 77 }

  condition:
    any of them
}