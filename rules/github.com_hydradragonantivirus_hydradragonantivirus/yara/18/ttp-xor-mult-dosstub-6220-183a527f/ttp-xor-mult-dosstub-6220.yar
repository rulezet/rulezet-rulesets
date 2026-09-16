rule TTP_XOR_MULT_DOSStub_6220 {
  strings:
    $key_6220 = { 36 48 [2] 42 50 [2] 05 52 [2] 42 43 [2] 0c 4f [2] 00 45 [2] 17 4e [2] 0c 00 [2] 31 }

  condition:
    any of them
}