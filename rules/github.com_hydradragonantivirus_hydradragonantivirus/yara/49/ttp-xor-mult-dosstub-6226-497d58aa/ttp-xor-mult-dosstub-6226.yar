rule TTP_XOR_MULT_DOSStub_6226 {
  strings:
    $key_6226 = { 36 4e [2] 42 56 [2] 05 54 [2] 42 45 [2] 0c 49 [2] 00 43 [2] 17 48 [2] 0c 06 [2] 31 }

  condition:
    any of them
}