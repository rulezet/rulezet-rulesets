rule TTP_XOR_MULT_DOSStub_1e36 {
  strings:
    $key_1e36 = { 4a 5e [2] 3e 46 [2] 79 44 [2] 3e 55 [2] 70 59 [2] 7c 53 [2] 6b 58 [2] 70 16 [2] 4d }

  condition:
    any of them
}