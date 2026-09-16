rule TTP_XOR_MULT_DOSStub_3920 {
  strings:
    $key_3920 = { 6d 48 [2] 19 50 [2] 5e 52 [2] 19 43 [2] 57 4f [2] 5b 45 [2] 4c 4e [2] 57 00 [2] 6a }

  condition:
    any of them
}