rule TTP_XOR_MULT_DOSStub_7920 {
  strings:
    $key_7920 = { 2d 48 [2] 59 50 [2] 1e 52 [2] 59 43 [2] 17 4f [2] 1b 45 [2] 0c 4e [2] 17 00 [2] 2a }

  condition:
    any of them
}