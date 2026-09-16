rule TTP_XOR_MULT_DOSStub_340c {
  strings:
    $key_340c = { 60 64 [2] 14 7c [2] 53 7e [2] 14 6f [2] 5a 63 [2] 56 69 [2] 41 62 [2] 5a 2c [2] 67 }

  condition:
    any of them
}