rule TTP_XOR_MULT_DOSStub_3741 {
  strings:
    $key_3741 = { 63 29 [2] 17 31 [2] 50 33 [2] 17 22 [2] 59 2e [2] 55 24 [2] 42 2f [2] 59 61 [2] 64 }

  condition:
    any of them
}