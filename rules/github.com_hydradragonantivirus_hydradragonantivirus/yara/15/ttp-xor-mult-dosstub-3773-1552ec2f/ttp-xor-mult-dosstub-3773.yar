rule TTP_XOR_MULT_DOSStub_3773 {
  strings:
    $key_3773 = { 63 1b [2] 17 03 [2] 50 01 [2] 17 10 [2] 59 1c [2] 55 16 [2] 42 1d [2] 59 53 [2] 64 }

  condition:
    any of them
}