rule TTP_XOR_MULT_DOSStub_0b3b {
  strings:
    $key_0b3b = { 5f 53 [2] 2b 4b [2] 6c 49 [2] 2b 58 [2] 65 54 [2] 69 5e [2] 7e 55 [2] 65 1b [2] 58 }

  condition:
    any of them
}