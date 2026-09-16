rule TTP_XOR_MULT_DOSStub_3e36 {
  strings:
    $key_3e36 = { 6a 5e [2] 1e 46 [2] 59 44 [2] 1e 55 [2] 50 59 [2] 5c 53 [2] 4b 58 [2] 50 16 [2] 6d }

  condition:
    any of them
}