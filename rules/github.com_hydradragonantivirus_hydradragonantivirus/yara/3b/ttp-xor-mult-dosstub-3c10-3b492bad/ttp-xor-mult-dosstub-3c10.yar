rule TTP_XOR_MULT_DOSStub_3c10 {
  strings:
    $key_3c10 = { 68 78 [2] 1c 60 [2] 5b 62 [2] 1c 73 [2] 52 7f [2] 5e 75 [2] 49 7e [2] 52 30 [2] 6f }

  condition:
    any of them
}