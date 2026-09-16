rule TTP_XOR_MULT_DOSStub_150c {
  strings:
    $key_150c = { 41 64 [2] 35 7c [2] 72 7e [2] 35 6f [2] 7b 63 [2] 77 69 [2] 60 62 [2] 7b 2c [2] 46 }

  condition:
    any of them
}